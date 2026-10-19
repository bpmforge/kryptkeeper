import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Button, Dialog, Input, Select } from "./ui";
import {
  JUSTIFICATIONS,
  MAX_EXCEPTION_DAYS,
  MAX_NOTE_LENGTH,
  expiresAtFromDays,
  proposeException,
  type ExceptionRequest,
} from "../lib/exceptionsApi";

export type AcceptRiskTarget = { type: "certificate" | "ca" | "target_file"; id: string };

type Props = {
  open: boolean;
  onClose: () => void;
  // null lets the caller render the dialog before a target is chosen.
  target: AcceptRiskTarget | null;
  findingCode?: string;
  // Offered as a Select when there is no fixed finding code.
  findingCodes?: readonly string[];
  // When set, the target id is typed by the operator (pages with no finding rows).
  editableTarget?: boolean;
  onProposed?: () => void;
};

function AcceptRiskForm({ target, findingCode, findingCodes, editableTarget, onClose, onProposed }: Props) {
  const [targetId, setTargetId] = useState(target?.id ?? "");
  const [code, setCode] = useState(findingCode ?? findingCodes?.[0] ?? "");
  const [justification, setJustification] = useState<string>(JUSTIFICATIONS[0].value);
  const [days, setDays] = useState("90");
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);

  const daysNum = Number(days);
  const daysValid = days.trim() !== "" && Number.isInteger(daysNum) && daysNum >= 1 && daysNum <= MAX_EXCEPTION_DAYS;
  const noteValid = note.length <= MAX_NOTE_LENGTH;
  const ready = daysValid && noteValid && targetId.trim() !== "" && code !== "";

  const mutation = useMutation({
    mutationFn: () => {
      const body: ExceptionRequest = {
        target_type: target?.type ?? "certificate",
        target_id: targetId.trim(),
        finding_code: code,
        justification_code: justification as ExceptionRequest["justification_code"],
        expires_at: expiresAtFromDays(daysNum),
        ...(note.trim() ? { justification_note: note.trim() } : {}),
      };
      return proposeException(body);
    },
    onSuccess: () => {
      setError(null);
      // Refetch only; the funnel changes once a second approver approves.
      onProposed?.();
    },
    onError: (err: Error) => setError(err.message),
  });

  if (mutation.isSuccess) {
    return (
      <div className="space-y-4" data-testid="accept-risk-pending">
        <p className="text-sm text-foreground">
          Pending approval — a second approver must approve this in{" "}
          <Link className="text-primary underline" to="/inbox">
            Approvals
          </Link>
          .
        </p>
        <p className="text-xs text-muted-foreground">
          Nothing is suppressed until then; the finding still counts as effective.
        </p>
        <div className="flex justify-end">
          <Button tone="secondary" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    );
  }

  return (
    <form
      className="space-y-4"
      onSubmit={(e) => {
        e.preventDefault();
        if (ready && !mutation.isPending) mutation.mutate();
      }}
    >
      {error ? (
        <p role="alert" className="text-sm text-state-over">
          {error}
        </p>
      ) : null}
      <label className="block space-y-1 text-sm text-foreground">
        <span>{target?.type === "ca" ? "CA id" : "Certificate fingerprint"}</span>
        <Input
          aria-label="Target"
          value={targetId}
          readOnly={!editableTarget}
          onChange={(e) => setTargetId(e.target.value)}
        />
      </label>
      <label className="block space-y-1 text-sm text-foreground">
        <span>Finding</span>
        {findingCode || !findingCodes ? (
          <Input aria-label="Finding code" value={code} readOnly />
        ) : (
          <Select aria-label="Finding code" value={code} onChange={(e) => setCode(e.target.value)}>
            {findingCodes.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </Select>
        )}
      </label>
      <label className="block space-y-1 text-sm text-foreground">
        <span>Justification</span>
        <Select
          aria-label="Justification"
          value={justification}
          onChange={(e) => setJustification(e.target.value)}
        >
          {JUSTIFICATIONS.map((j) => (
            <option key={j.value} value={j.value}>
              {j.label}
            </option>
          ))}
        </Select>
      </label>
      <label className="block space-y-1 text-sm text-foreground">
        <span>Expires in (days, max {MAX_EXCEPTION_DAYS})</span>
        <Input
          aria-label="Expiry days"
          type="number"
          min={1}
          max={MAX_EXCEPTION_DAYS}
          value={days}
          onChange={(e) => setDays(e.target.value)}
        />
        {!daysValid ? (
          <span role="alert" className="text-xs text-state-over">
            Enter a whole number of days between 1 and {MAX_EXCEPTION_DAYS}.
          </span>
        ) : null}
      </label>
      <label className="block space-y-1 text-sm text-foreground">
        <span>Note (optional)</span>
        <Input
          aria-label="Justification note"
          maxLength={MAX_NOTE_LENGTH}
          value={note}
          onChange={(e) => setNote(e.target.value)}
        />
      </label>
      <div className="flex justify-end gap-2">
        <Button type="button" tone="secondary" onClick={onClose}>
          Cancel
        </Button>
        <Button type="submit" disabled={!ready || mutation.isPending}>
          {mutation.isPending ? "Submitting…" : "Propose exception"}
        </Button>
      </div>
    </form>
  );
}

export function AcceptRiskDialog(props: Props) {
  const { open, onClose, target, editableTarget } = props;
  if (!target && !editableTarget) return null;
  return (
    <Dialog
      open={open}
      title="Accept risk"
      description="Propose an exception for this finding. It needs a second approver and expires on the date you choose."
      onClose={onClose}
    >
      {/* key resets the form every time the dialog reopens or retargets */}
      <AcceptRiskForm key={`${open}:${target?.id ?? ""}:${props.findingCode ?? ""}`} {...props} />
    </Dialog>
  );
}
