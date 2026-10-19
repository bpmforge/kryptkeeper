// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

// W27-21: Route 53 dns-01 adapter. Hand-rolled signed XML REST (no AWS SDK
// service module), signing with the SigV4 signer awsPCASource already uses.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const (
	route53APIBase = "https://route53.amazonaws.com"
)

func init() { registerDNSProvider("route53", newRoute53DNSFromConfig) }

type route53DNS struct {
	accessKey, secretKey, sessionToken, zoneID string

	apiBase string
	client  *http.Client
	now     func() time.Time

	mu    sync.Mutex
	zones map[string]route53Zone // fqdn -> zone (guarded by mu via presentRRSet)
	ttl   map[string]int64       // fqdn -> ttl of the rrset as read
}

type route53Zone struct{ id, name string }

func newRoute53DNSFromConfig(_ acmeConnectorConfig, p acmeCredentialPayload) (dnsProvider, error) {
	var d struct {
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
		SessionToken    string `json:"session_token"`
		HostedZoneID    string `json:"hosted_zone_id"`
	}
	if len(p.DNS) == 0 || json.Unmarshal(p.DNS, &d) != nil || d.AccessKeyID == "" || d.SecretAccessKey == "" {
		return nil, errors.New(`acme connector dns_provider route53 needs a "dns" object in its credential (access_key_id, secret_access_key)`)
	}
	return &route53DNS{
		accessKey: d.AccessKeyID, secretKey: d.SecretAccessKey, sessionToken: d.SessionToken,
		zoneID:  strings.TrimPrefix(d.HostedZoneID, "/hostedzone/"),
		apiBase: route53APIBase, client: dnsAPIClient(), now: time.Now,
		zones: map[string]route53Zone{}, ttl: map[string]int64{},
	}, nil
}

func (r *route53DNS) secrets() []string {
	return []string{r.accessKey, r.secretKey, r.sessionToken}
}

type route53Error struct {
	Error struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
}

// call does one signed request. Errors carry AWS's code and message, never
// credentials or request bodies.
func (r *route53DNS) call(ctx context.Context, method, path string, q url.Values, body []byte) ([]byte, error) {
	u := r.apiBase + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd *bytes.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "text/xml")
	}
	sum := sha256.Sum256(body)
	creds := aws.Credentials{AccessKeyID: r.accessKey, SecretAccessKey: r.secretKey, SessionToken: r.sessionToken}
	if err := v4.NewSigner().SignHTTP(ctx, creds, req, hex.EncodeToString(sum[:]), "route53", "us-east-1", r.now()); err != nil {
		return nil, fmt.Errorf("route53 sign: %s", redact(err.Error(), r.secrets()...))
	}
	status, resp, err := dnsRoundTrip(r.client, req)
	if err != nil {
		return nil, fmt.Errorf("route53 %s %s: %s", method, path, redact(err.Error(), r.secrets()...))
	}
	if status >= 300 {
		var e route53Error
		msg := ""
		if xml.Unmarshal(resp, &e) == nil && e.Error.Code != "" {
			msg = ": " + e.Error.Code + " " + e.Error.Message
		}
		return nil, fmt.Errorf("route53 %s %s: HTTP %d%s", method, path, status, snippet(redact(msg, r.secrets()...)))
	}
	return resp, nil
}

func (r *route53DNS) zoneFor(ctx context.Context, fqdn string) (string, error) {
	if r.zoneID != "" {
		raw, err := r.call(ctx, http.MethodGet, "/2013-04-01/hostedzone/"+url.PathEscape(r.zoneID), nil, nil)
		if err != nil {
			return "", err
		}
		var gz struct {
			HostedZone struct {
				Name string `xml:"Name"`
			} `xml:"HostedZone"`
		}
		if err := xml.Unmarshal(raw, &gz); err != nil || gz.HostedZone.Name == "" {
			return "", errors.New("route53: hosted zone response is unreadable")
		}
		name := strings.TrimSuffix(strings.ToLower(gz.HostedZone.Name), ".")
		if fqdn != name && !strings.HasSuffix(fqdn, "."+name) {
			return "", fmt.Errorf("route53 hosted zone %s does not hold %s", name, fqdn)
		}
		r.zones[fqdn] = route53Zone{id: r.zoneID, name: name}
		return name, nil
	}
	for _, cand := range parentCandidates(fqdn) {
		raw, err := r.call(ctx, http.MethodGet, "/2013-04-01/hostedzonesbyname",
			url.Values{"dnsname": {cand}, "maxitems": {"1"}}, nil)
		if err != nil {
			return "", err
		}
		var list struct {
			Zones []struct {
				ID     string `xml:"Id"`
				Name   string `xml:"Name"`
				Config struct {
					Private bool `xml:"PrivateZone"`
				} `xml:"Config"`
			} `xml:"HostedZones>HostedZone"`
		}
		if err := xml.Unmarshal(raw, &list); err != nil {
			return "", errors.New("route53: hosted zone list is unreadable")
		}
		for _, z := range list.Zones {
			if strings.EqualFold(z.Name, cand+".") && !z.Config.Private {
				id := strings.TrimPrefix(z.ID, "/hostedzone/")
				r.zones[fqdn] = route53Zone{id: id, name: cand}
				return cand, nil
			}
		}
	}
	return "", fmt.Errorf("no Route 53 public hosted zone these credentials can see holds %s", fqdn)
}

type route53RRSet struct {
	Name    string `xml:"Name"`
	Type    string `xml:"Type"`
	TTL     int64  `xml:"TTL"`
	Records []struct {
		Value string `xml:"Value"`
	} `xml:"ResourceRecords>ResourceRecord"`
}

func (r *route53DNS) read(ctx context.Context, fqdn string) ([]string, error) {
	z := r.zones[fqdn]
	raw, err := r.call(ctx, http.MethodGet, "/2013-04-01/hostedzone/"+url.PathEscape(z.id)+"/rrset",
		url.Values{"name": {fqdn + "."}, "type": {"TXT"}, "maxitems": {"1"}}, nil)
	if err != nil {
		return nil, err
	}
	var list struct {
		Sets []route53RRSet `xml:"ResourceRecordSets>ResourceRecordSet"`
	}
	if err := xml.Unmarshal(raw, &list); err != nil {
		return nil, errors.New("route53: record set response is unreadable")
	}
	for _, s := range list.Sets {
		if strings.EqualFold(s.Name, fqdn+".") && s.Type == "TXT" {
			vals := make([]string, 0, len(s.Records))
			for _, rec := range s.Records {
				vals = append(vals, rec.Value)
			}
			r.ttl[fqdn] = s.TTL
			return vals, nil
		}
	}
	return nil, nil
}

func (r *route53DNS) write(ctx context.Context, fqdn string, old, next []string) error {
	z := r.zones[fqdn]
	action, values, ttl := "UPSERT", next, int64(60)
	if len(next) == 0 {
		// DELETE must echo exactly what Route 53 holds.
		action, values = "DELETE", old
		if t := r.ttl[fqdn]; t > 0 {
			ttl = t
		}
	}
	type rec struct {
		Value string `xml:"Value"`
	}
	type rrs struct {
		Name    string `xml:"Name"`
		Type    string `xml:"Type"`
		TTL     int64  `xml:"TTL"`
		Records []rec  `xml:"ResourceRecords>ResourceRecord"`
	}
	type change struct {
		Action string `xml:"Action"`
		RRSet  rrs    `xml:"ResourceRecordSet"`
	}
	req := struct {
		XMLName xml.Name `xml:"https://route53.amazonaws.com/doc/2013-04-01/ ChangeResourceRecordSetsRequest"`
		Changes []change `xml:"ChangeBatch>Changes>Change"`
	}{}
	set := rrs{Name: fqdn + ".", Type: "TXT", TTL: ttl}
	for _, v := range values {
		set.Records = append(set.Records, rec{Value: v})
	}
	req.Changes = []change{{Action: action, RRSet: set}}
	body, err := xml.Marshal(req)
	if err != nil {
		return err
	}
	_, err = r.call(ctx, http.MethodPost, "/2013-04-01/hostedzone/"+url.PathEscape(z.id)+"/rrset/", nil, body)
	return err
}

func (r *route53DNS) quote(v string) string { return quoteTXT(v) }

func (r *route53DNS) Present(ctx context.Context, fqdn, value string) (string, func(context.Context) error, error) {
	return presentRRSet(ctx, &r.mu, r, fqdn, value)
}
