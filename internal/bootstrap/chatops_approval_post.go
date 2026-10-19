// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"kryptkeeper/internal/logging"
	"kryptkeeper/internal/notifications/chatops/teams"
	"kryptkeeper/internal/notifications/delivery"
)

// W32-27: posts approval requests to the owner team's Slack / Teams channel
// and edits the message when the request is decided or expires. Everything
// here is best-effort and off the request path: a store write that succeeded
// enqueues an event, one worker delivers it, and a failure is logged only.

const (
	cfgSlackTeamChannels = "notifications.slack_team_channels"
	cfgSlackBotToken     = "notifications.slack_bot_token"
	cfgTeamsTeamChannels = "notifications.teams_team_channels"
	cfgTeamsAppID        = "notifications.teams_app_id"
	cfgTeamsAppPassword  = "notifications.teams_app_password"

	chatopsPostQueueSize = 256
	chatopsPostTimeout   = 30 * time.Second

	chatopsKindApproval = "approval"
	chatopsKindAction   = "action"
)

// approvalLifecycleHooks is the seam the approval stores call after a
// successful Create / Decide. Nil (the default) is a no-op.
type approvalLifecycleHooks struct {
	pending func(ev chatopsApprovalEvent)
	decided func(ev chatopsApprovalEvent)
}

var approvalLifecycle atomic.Pointer[approvalLifecycleHooks]

// chatopsApprovalEvent carries values only (never a request context).
type chatopsApprovalEvent struct {
	Kind, ID   string // "approval" | "action"
	OwnerTeam  string
	Summary    string
	Requester  string
	ExpiresAt  time.Time
	Result     string // decided only: approved | rejected | expired
	By         string
	ExternalBy string
	At         time.Time
}

func (e chatopsApprovalEvent) key() string { return e.Kind + ":" + e.ID }

// notifyApprovalPending is called by the stores after a successful Create.
func notifyApprovalPending(ev chatopsApprovalEvent) {
	if h := approvalLifecycle.Load(); h != nil && h.pending != nil {
		h.pending(ev)
	}
}

// notifyApprovalDecided is called by the stores after a successful Decide, on
// every channel (ui, itsm, chatops, expiry sweeper). "executing" is the
// pending-action claim, not an outcome, and is ignored.
func notifyApprovalDecided(ctx context.Context, kind, id, status, by string) {
	h := approvalLifecycle.Load()
	if h == nil || h.decided == nil {
		return
	}
	ev := chatopsApprovalEvent{Kind: kind, ID: id, By: by, At: time.Now().UTC()}
	switch status {
	case "approved", "failed": // failed = approved, then execution failed
		ev.Result = "approved"
	case "rejected":
		ev.Result = "rejected"
		if by == expirySweeper {
			ev.Result, ev.By = "expired", ""
		}
	default:
		return
	}
	if ch := ApprovalChannelFrom(ctx); ch.Name != ChannelUI {
		ev.ExternalBy = ch.ExternalID
	}
	h.decided(ev)
}

func pendingActionOwnerTeam(params json.RawMessage) string {
	var p struct {
		OwnerTeam string `json:"owner_team"`
		TeamID    string `json:"team_id"`
	}
	if json.Unmarshal(params, &p) != nil {
		return ""
	}
	if p.OwnerTeam != "" {
		return p.OwnerTeam
	}
	return p.TeamID
}

func approvalPendingEvent(req ApprovalRequest) chatopsApprovalEvent {
	summary := "Certificate issuance (template " + req.TemplateID + ", CA " + req.CAID + ")"
	if req.Kind == approvalKindSSH {
		summary = "SSH certificate issuance"
	}
	return chatopsApprovalEvent{Kind: chatopsKindApproval, ID: req.ID, OwnerTeam: req.TeamID, Summary: summary,
		Requester: req.Requester, ExpiresAt: time.Now().Add(ApprovalTTL())}
}

func pendingActionPendingEvent(a PendingAction) chatopsApprovalEvent {
	summary := a.ActionType
	if a.Rationale != "" {
		summary += ": " + a.Rationale
	}
	return chatopsApprovalEvent{Kind: chatopsKindAction, ID: a.ID, OwnerTeam: pendingActionOwnerTeam(a.Params),
		Summary: summary, Requester: a.ProposedBy, ExpiresAt: time.Now().Add(ApprovalTTL())}
}

// --- durable message references (self-healing sidecar table) ---

const chatopsMessageRefSchema = `
CREATE TABLE IF NOT EXISTS chatops_message_refs (
    platform TEXT NOT NULL, approval_key TEXT NOT NULL, team TEXT NOT NULL,
    channel TEXT NOT NULL, ref TEXT NOT NULL, service_url TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    PRIMARY KEY (platform, approval_key));`

// chatopsMsgRef is where an approval message was posted. Ref is the Slack ts
// or the Teams activity id.
type chatopsMsgRef struct {
	Team, Channel, Ref, ServiceURL string
}

type chatopsRefStore struct {
	db *sql.DB
	ph func(int) string
}

func (s *chatopsRefStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, chatopsMessageRefSchema)
	return err
}

// retryBusy retries a sidecar-table call a few times: the worker races the
// request path's writes and a briefly locked SQLite DB must not lose an update.
func retryBusy(fn func() error) error {
	var err error
	for i := 0; i < 5; i++ {
		if err = fn(); err == nil {
			return nil
		}
		time.Sleep(time.Duration(i+1) * 50 * time.Millisecond)
	}
	return err
}

func (s *chatopsRefStore) put(ctx context.Context, platform, key string, r chatopsMsgRef) error {
	return retryBusy(func() error { return s.putOnce(ctx, platform, key, r) })
}

func (s *chatopsRefStore) putOnce(ctx context.Context, platform, key string, r chatopsMsgRef) error {
	q := fmt.Sprintf(`INSERT INTO chatops_message_refs (platform, approval_key, team, channel, ref, service_url, created_at)
		VALUES (%s, %s, %s, %s, %s, %s, %s)
		ON CONFLICT (platform, approval_key) DO UPDATE SET team = excluded.team, channel = excluded.channel,
		ref = excluded.ref, service_url = excluded.service_url, created_at = excluded.created_at`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7))
	_, err := s.db.ExecContext(ctx, q, platform, key, r.Team, r.Channel, r.Ref, r.ServiceURL, time.Now().UTC().Format(time.RFC3339))
	return err
}

func (s *chatopsRefStore) get(ctx context.Context, platform, key string) (r chatopsMsgRef, ok bool, err error) {
	err = retryBusy(func() error {
		var e error
		r, ok, e = s.getOnce(ctx, platform, key)
		return e
	})
	return r, ok, err
}

func (s *chatopsRefStore) getOnce(ctx context.Context, platform, key string) (chatopsMsgRef, bool, error) {
	var r chatopsMsgRef
	err := s.db.QueryRowContext(ctx, fmt.Sprintf(
		`SELECT team, channel, ref, service_url FROM chatops_message_refs WHERE platform = %s AND approval_key = %s`,
		s.ph(1), s.ph(2)), platform, key).Scan(&r.Team, &r.Channel, &r.Ref, &r.ServiceURL)
	if errors.Is(err, sql.ErrNoRows) {
		return chatopsMsgRef{}, false, nil
	}
	return r, err == nil, err
}

// slackRefs adapts the table to delivery.RefStore for one team.
type slackRefs struct {
	s    *chatopsRefStore
	team string
}

func (r slackRefs) Put(ctx context.Context, key string, ref delivery.MessageRef) error {
	return r.s.put(ctx, "slack", key, chatopsMsgRef{Team: r.team, Channel: ref.Channel, Ref: ref.TS})
}

func (r slackRefs) Get(ctx context.Context, key string) (delivery.MessageRef, bool, error) {
	m, ok, err := r.s.get(ctx, "slack", key)
	return delivery.MessageRef{Channel: m.Channel, TS: m.Ref}, ok, err
}

// --- config-backed team -> channel resolvers ---

// configString reads key from the runtime config store, falling back to env
// (via the registry's EnvVar) when there is no override. Secret values never
// leave this package's call stack.
func configString(ctx context.Context, store ConfigStore, key, envVar string, secret bool) string {
	if store != nil {
		if secret {
			if v, err := store.Resolve(ctx, key); err == nil {
				return strings.TrimSpace(string(v))
			}
		} else if e, ok, err := store.Get(ctx, key); err == nil && ok {
			return strings.TrimSpace(e.Value)
		}
	}
	return strings.TrimSpace(os.Getenv(envVar))
}

// slackTeamChannels parses notifications.slack_team_channels (JSON object
// team -> channel id) into a resolver. Malformed JSON yields an error and no
// resolver, never a default channel.
func slackTeamChannels(raw string) (delivery.MapResolver, error) {
	if raw == "" {
		return nil, nil
	}
	m := map[string]string{}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, errors.New("not a JSON object of team to channel id")
	}
	return delivery.MapResolver(m), nil
}

// teamsTeamChannels parses notifications.teams_team_channels: JSON object
// team -> {"service_url":..., "conversation_id":...}.
func teamsTeamChannels(raw string) (teams.MapResolver, error) {
	if raw == "" {
		return nil, nil
	}
	var m map[string]struct {
		ServiceURL     string `json:"service_url"`
		ConversationID string `json:"conversation_id"`
	}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, errors.New("not a JSON object of team to {service_url, conversation_id}")
	}
	out := teams.MapResolver{}
	for t, c := range m {
		out[t] = teams.ChannelRef{ServiceURL: c.ServiceURL, ConversationID: c.ConversationID}
	}
	return out, nil
}

// --- notifier ---

type chatopsApprovalNotifier struct {
	cfg  ConfigStore // may be nil: env only
	refs *chatopsRefStore

	// test seams
	httpClient    *http.Client
	slackBaseURL  string
	teamsTokenURL string

	queue chan func()
	wg    sync.WaitGroup
}

func newChatopsApprovalNotifier(cfg ConfigStore, refs *chatopsRefStore) *chatopsApprovalNotifier {
	n := &chatopsApprovalNotifier{cfg: cfg, refs: refs, queue: make(chan func(), chatopsPostQueueSize)}
	go func() {
		for job := range n.queue {
			job()
			n.wg.Done()
		}
	}()
	return n
}

// enqueue never blocks the caller: a full queue drops the event with a log line.
func (n *chatopsApprovalNotifier) enqueue(what string, job func(ctx context.Context)) {
	n.wg.Add(1)
	run := func() {
		ctx, cancel := context.WithTimeout(context.Background(), chatopsPostTimeout)
		defer cancel()
		defer func() {
			if r := recover(); r != nil {
				logging.Warnf("chatops approval %s: panic recovered", what)
			}
		}()
		job(ctx)
	}
	select {
	case n.queue <- run:
	default:
		n.wg.Done()
		logging.Warnf("chatops approval %s: queue full, event dropped", what)
	}
}

// drain waits for queued events (tests).
func (n *chatopsApprovalNotifier) drain() { n.wg.Wait() }

func (n *chatopsApprovalNotifier) hooks() *approvalLifecycleHooks {
	return &approvalLifecycleHooks{
		pending: func(ev chatopsApprovalEvent) {
			n.enqueue("post", func(ctx context.Context) { n.post(ctx, ev) })
		},
		decided: func(ev chatopsApprovalEvent) {
			n.enqueue("update", func(ctx context.Context) { n.update(ctx, ev) })
		},
	}
}

func (n *chatopsApprovalNotifier) slack(ctx context.Context, team string) (*delivery.SlackInteractive, error) {
	token := configString(ctx, n.cfg, cfgSlackBotToken, "SLACK_BOT_TOKEN", true)
	if token == "" {
		return nil, nil
	}
	res, err := slackTeamChannels(configString(ctx, n.cfg, cfgSlackTeamChannels, "SLACK_TEAM_CHANNELS", false))
	if err != nil || res == nil {
		return nil, err
	}
	var refs delivery.RefStore
	if n.refs != nil {
		refs = slackRefs{s: n.refs, team: team}
	}
	return &delivery.SlackInteractive{BotToken: token, BaseURL: n.slackBaseURL, Resolver: res, Refs: refs, HTTP: n.httpClient}, nil
}

func (n *chatopsApprovalNotifier) teamsPoster(ctx context.Context) (*teams.Poster, error) {
	id := configString(ctx, n.cfg, cfgTeamsAppID, "TEAMS_APP_ID", false)
	pw := configString(ctx, n.cfg, cfgTeamsAppPassword, "TEAMS_APP_PASSWORD", true)
	if id == "" || pw == "" {
		return nil, nil
	}
	res, err := teamsTeamChannels(configString(ctx, n.cfg, cfgTeamsTeamChannels, "TEAMS_TEAM_CHANNELS", false))
	if err != nil || res == nil {
		return nil, err
	}
	return &teams.Poster{AppID: id, AppPassword: pw, TokenURL: n.teamsTokenURL, HTTP: n.httpClient, Resolver: res}, nil
}

func (n *chatopsApprovalNotifier) post(ctx context.Context, ev chatopsApprovalEvent) {
	if ev.OwnerTeam == "" {
		return // no owner team: never broadcast
	}
	if s, err := n.slack(ctx, ev.OwnerTeam); err != nil {
		logging.Warnf("chatops slack approval post skipped: %s: %v", cfgSlackTeamChannels, err)
	} else if s != nil {
		_, err := s.PostApproval(ctx, delivery.ApprovalPending{Kind: ev.Kind, ID: ev.ID, OwnerTeam: ev.OwnerTeam,
			Summary: ev.Summary, Requester: ev.Requester, ExpiresAt: ev.ExpiresAt})
		if err != nil && !errors.Is(err, delivery.ErrNoTeamChannel) {
			logging.Warnf("chatops slack approval post failed id=%s: %v", ev.key(), err)
		}
	}
	p, err := n.teamsPoster(ctx)
	if err != nil {
		logging.Warnf("chatops teams approval post skipped: %s: %v", cfgTeamsTeamChannels, err)
		return
	}
	if p == nil {
		return
	}
	ref, activityID, err := p.PostApprovalRef(ctx, ev.OwnerTeam, ev.Kind, ev.ID, ev.Summary, ev.Requester, ev.ExpiresAt)
	if err != nil {
		if !errors.Is(err, teams.ErrNoTeamChannel) {
			logging.Warnf("chatops teams approval post failed id=%s: %v", ev.key(), err)
		}
		return
	}
	if n.refs != nil && activityID != "" {
		if err := n.refs.put(ctx, "teams", ev.key(), chatopsMsgRef{Team: ev.OwnerTeam, Channel: ref.ConversationID, Ref: activityID, ServiceURL: ref.ServiceURL}); err != nil {
			logging.Warnf("chatops teams approval ref not stored id=%s: %v", ev.key(), err)
		}
	}
}

func chatopsOutcomeText(ev chatopsApprovalEvent) string {
	if ev.Result == "expired" {
		return "Expired - no decision was made before the request expired. Nothing was changed. Raise the request again if still needed."
	}
	text := strings.ToUpper(ev.Result[:1]) + ev.Result[1:] + " by " + ev.By
	if ev.ExternalBy != "" {
		text += " (via " + ev.ExternalBy + ")"
	}
	return text + " at " + ev.At.UTC().Format(time.RFC3339)
}

func (n *chatopsApprovalNotifier) update(ctx context.Context, ev chatopsApprovalEvent) {
	if n.refs == nil {
		return
	}
	if _, ok, err := n.refs.get(ctx, "slack", ev.key()); err != nil {
		logging.Warnf("chatops slack ref lookup failed id=%s: %v", ev.key(), err)
	} else if ok {
		s, serr := n.slack(ctx, "")
		if s == nil {
			if serr != nil {
				logging.Warnf("chatops slack approval update skipped: %v", serr)
			}
		} else if err := s.UpdateOutcome(ctx, ev.key(), delivery.Outcome{Result: ev.Result, By: ev.By, ExternalBy: ev.ExternalBy, At: ev.At}); err != nil {
			logging.Warnf("chatops slack approval update failed id=%s: %v", ev.key(), err)
		}
	}
	r, ok, err := n.refs.get(ctx, "teams", ev.key())
	if err != nil {
		logging.Warnf("chatops teams ref lookup failed id=%s: %v", ev.key(), err)
		return
	}
	if !ok {
		return
	}
	p, perr := n.teamsPoster(ctx)
	if p == nil {
		if perr != nil {
			logging.Warnf("chatops teams approval update skipped: %v", perr)
		}
		return
	}
	if err := p.UpdateActivity(ctx, teams.ChannelRef{ServiceURL: r.ServiceURL, ConversationID: r.Channel}, r.Ref, chatopsOutcomeText(ev)); err != nil {
		logging.Warnf("chatops teams approval update failed id=%s: %v", ev.key(), err)
	}
}

// startChatopsApprovalPosting installs the notifier behind the approval
// stores' lifecycle hooks, borrowing the pending-action store's DB handle for
// the message-reference table (same pattern as chatopsIdentityStoreForActions).
// Other store types, or a schema failure, leave posting off.
// chatopsRefStoreForActions derives the message-reference store from the
// pending-action store's DB handle (same database, self-healing sidecar
// table); other store types, or a schema failure, yield nil.
func chatopsRefStoreForActions(actions PendingActionStore) *chatopsRefStore {
	p, ok := actions.(*dbPendingActionStore)
	if !ok || p == nil {
		return nil
	}
	refs := &chatopsRefStore{db: p.db, ph: p.ph}
	if err := refs.EnsureSchema(context.Background()); err != nil {
		logging.Warnf("chatops message ref schema unavailable, approval posting off: %v", err)
		return nil
	}
	return refs
}

// startChatopsApprovalPosting installs the notifier behind the approval
// stores' lifecycle hooks. Without a durable ref store posting stays off.
func startChatopsApprovalPosting(actions PendingActionStore) {
	if refs := chatopsRefStoreForActions(actions); refs != nil {
		approvalLifecycle.Store(newChatopsApprovalNotifier(NewConfigStoreFromEnv(), refs).hooks())
	}
}
