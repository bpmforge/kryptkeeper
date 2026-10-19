import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Badge, Button, Dialog, Input, Textarea } from "./ui";
import { fetchJSON } from "../lib/api";
import type { PolicyRules } from "../lib/policiesApi";

const MAX_NAME = 120;
const MAX_TEXT = 2000;

type DraftRequest = { name: string; text: string };
type DraftResult = {
  policy: {
    name: string;
    enabled: boolean;
    ca_id?: string;
    rules: PolicyRules;
  };
  explanation: string[];
  unrecognized: string[];
  persisted?: boolean;
};
type SubmitResult = {
  policy_id?: string;
  pending_action_id?: string;
  status?: string;
  enabled?: boolean;
  unrecognized?: string[];
};

// POST /policies/draft is a pure parse; POST /policies/draft/submit re-parses
// server-side and only files a disabled policy plus a pending approval.
const draftPolicy = (body: DraftRequest) =>
  fetchJSON<{ data: DraftResult }>("/policies/draft", {
    method: "POST",
    body: JSON.stringify(body),
  });
const submitPolicyDraft = (body: DraftRequest) =>
  fetchJSON<{ data: SubmitResult }>("/policies/draft/submit", {
    method: "POST",
    body: JSON.stringify(body),
  });

function friendly(err: Error): string {
  // The api client attaches `status`; the message regex is a fallback for
  // errors that did not come through it.
  const forbidden =
    (err as { status?: number }).status === 403 ||
    /\b403\b|forbidden|not permitted/i.test(err.message);
  return forbidden
    ? "You do not have permission to draft policies"
    : err.message;
}

type Props = { open: boolean; onClose: () => void };

function RuleRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between gap-4 text-sm">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="text-foreground">{value}</dd>
    </div>
  );
}

function PolicyDraftForm({ onClose }: { onClose: () => void }) {
  const [name, setName] = useState("");
  const [text, setText] = useState("");
  const [reviewed, setReviewed] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const parse = useMutation({
    mutationFn: () => draftPolicy({ name: name.trim(), text }),
    onSuccess: () => {
      setError(null);
      setReviewed(false);
    },
    onError: (e: Error) => setError(friendly(e)),
  });
  const submit = useMutation({
    mutationFn: () => submitPolicyDraft({ name: name.trim(), text }),
    onSuccess: () => setError(null),
    onError: (e: Error) => setError(friendly(e)),
  });

  const errorBlock = error ? (
    <p role="alert" className="text-sm text-state-over">
      {error}
    </p>
  ) : null;

  if (submit.isSuccess) {
    const id = submit.data.data.pending_action_id;
    return (
      <div className="space-y-4" data-testid="policy-draft-submitted">
        <p className="text-sm text-foreground">
          Submitted for approval. The draft policy is stored disabled; a
          different approver must review it before anything changes.
        </p>
        <div className="flex flex-wrap gap-4 text-sm">
          <Link className="text-primary underline" to="/policies">
            Open Policies
          </Link>
          {id ? (
            <Link
              className="text-primary underline"
              to={`/inbox?focus=pending_action:${encodeURIComponent(id)}`}
            >
              View approval request
            </Link>
          ) : null}
        </div>
        <div className="flex justify-end">
          <Button tone="secondary" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    );
  }

  const draft = parse.data?.data;
  if (!draft) {
    const ready =
      name.trim() !== "" &&
      name.length <= MAX_NAME &&
      text.trim() !== "" &&
      text.length <= MAX_TEXT;
    return (
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          if (ready && !parse.isPending) parse.mutate();
        }}
      >
        {errorBlock}
        <label className="block space-y-1 text-sm text-foreground">
          <span>Policy name</span>
          <Input
            aria-label="Policy name"
            maxLength={MAX_NAME}
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </label>
        <label className="block space-y-1 text-sm text-foreground">
          <span>Rules in plain English</span>
          <Textarea
            aria-label="Policy text"
            rows={5}
            maxLength={MAX_TEXT}
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
        </label>
        <p className="text-xs text-muted-foreground">
          Drafts always start disabled. Nothing is enforced until a different
          person approves it.
        </p>
        <div className="flex justify-end gap-2">
          <Button type="button" tone="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" disabled={!ready || parse.isPending}>
            {parse.isPending ? "Parsing…" : "Parse"}
          </Button>
        </div>
      </form>
    );
  }

  const unparsed = draft.unrecognized ?? [];
  const rules = draft.policy.rules ?? {};
  const gated = unparsed.length > 0 && !reviewed;
  return (
    <div className="space-y-4" data-testid="policy-draft-review">
      {errorBlock}
      <div className="flex items-center gap-2">
        <span className="text-sm font-medium text-foreground">
          {draft.policy.name}
        </span>
        <Badge tone="warning">Disabled until approved</Badge>
      </div>
      <section aria-label="Understood" className="space-y-1">
        <h3 className="text-sm font-medium text-foreground">Understood</h3>
        {draft.explanation.length > 0 ? (
          <ul className="list-disc pl-5 text-sm text-foreground">
            {draft.explanation.map((line, i) => (
              <li key={i}>{line}</li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted-foreground">
            Nothing was understood.
          </p>
        )}
      </section>
      <section aria-label="Parsed rules" className="space-y-1">
        <h3 className="text-sm font-medium text-foreground">
          Parsed rules (read-only)
        </h3>
        <dl className="space-y-1">
          <RuleRow
            label="Max validity days"
            value={String(rules.max_validity_days ?? "not set")}
          />
          <RuleRow
            label="Min RSA bits"
            value={String(rules.min_rsa_bits ?? "not set")}
          />
          <RuleRow
            label="Allowed algorithms"
            value={rules.allowed_algorithms?.join(", ") || "not set"}
          />
          <RuleRow
            label="Allow CA certificates"
            value={
              rules.allow_ca_certs === undefined
                ? "not set"
                : rules.allow_ca_certs
                  ? "yes"
                  : "no"
            }
          />
        </dl>
        <p className="text-xs text-muted-foreground">
          The server re-parses your text on submit; edit the text to change
          these rules.
        </p>
      </section>
      {unparsed.length > 0 ? (
        <div
          role="alert"
          className="space-y-1 rounded-lg border border-state-warn/40 p-3"
        >
          <h3 className="text-sm font-medium text-foreground">
            These phrases were not applied
          </h3>
          <ul className="list-disc pl-5 text-sm text-foreground">
            {unparsed.map((line, i) => (
              <li key={i}>{line}</li>
            ))}
          </ul>
        </div>
      ) : (
        <p className="text-sm text-muted-foreground">
          Every phrase was understood
        </p>
      )}
      {unparsed.length > 0 ? (
        <label className="flex items-center gap-2 text-sm text-foreground">
          <input
            type="checkbox"
            checked={reviewed}
            onChange={(e) => setReviewed(e.target.checked)}
          />
          <span>I reviewed the phrases that were not applied</span>
        </label>
      ) : null}
      <div className="flex justify-end gap-2">
        <Button type="button" tone="secondary" onClick={() => parse.reset()}>
          Back to text
        </Button>
        <Button
          type="button"
          disabled={gated || submit.isPending}
          onClick={() => submit.mutate()}
        >
          {submit.isPending
            ? "Submitting…"
            : unparsed.length > 0
              ? "Submit draft anyway"
              : "Submit draft"}
        </Button>
      </div>
    </div>
  );
}

export function PolicyDraftDialog({ open, onClose }: Props) {
  return (
    <Dialog
      open={open}
      title="Draft policy from text"
      description="Describe rules in plain English, check what was understood, then submit for approval."
      onClose={onClose}
    >
      <PolicyDraftForm key={String(open)} onClose={onClose} />
    </Dialog>
  );
}
