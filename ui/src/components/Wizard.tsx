import { useEffect, useRef, useState } from "react";
import { cn } from "@/lib/utils";
import { Button } from "./ui.tsx";

export interface WizardStepDef {
  id: string;
  title: string;
  // returns null when valid, or an error message; gates Next
  validate?: () => string | null;
  render: () => React.ReactNode;
}

export interface WizardProps {
  steps: WizardStepDef[];
  onComplete: () => void | Promise<void>;
  onCancel?: () => void;
  // optional final review step, rendered after the last WizardStepDef and
  // before Finish; state is whatever the consumer's own step components
  // already track (Wizard itself holds no form data)
  summary?: (state: unknown) => React.ReactNode;
  summaryState?: unknown;
}

// Wizard is a reusable multi-step flow: progress header, per-step validation
// gating Next, an optional review step before Finish. It is presentational +
// state-only (current step index, inline validation error) — the consuming
// page owns its own form state and data fetching.
export function Wizard({
  steps,
  onComplete,
  onCancel,
  summary,
  summaryState,
}: WizardProps) {
  const [index, setIndex] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [finishing, setFinishing] = useState(false);
  const headingRef = useRef<HTMLHeadingElement>(null);

  const totalSteps = steps.length + (summary ? 1 : 0);
  const onSummaryStep = summary != null && index === steps.length;
  const step = onSummaryStep ? null : steps[index];

  useEffect(() => {
    headingRef.current?.focus();
  }, [index]);

  const goNext = () => {
    if (step?.validate) {
      const message = step.validate();
      if (message) {
        setError(message);
        return;
      }
    }
    setError(null);
    setIndex((i) => i + 1);
  };

  const goBack = () => {
    setError(null);
    setIndex((i) => Math.max(0, i - 1));
  };

  const finish = async () => {
    if (step?.validate) {
      const message = step.validate();
      if (message) {
        setError(message);
        return;
      }
    }
    setError(null);
    setFinishing(true);
    try {
      await onComplete();
    } finally {
      setFinishing(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (e.key === "Escape") {
      onCancel?.();
      return;
    }
    if (e.key === "Enter" && !(e.target instanceof HTMLTextAreaElement)) {
      e.preventDefault();
      if (index === totalSteps - 1) {
        void finish();
      } else {
        goNext();
      }
    }
  };

  return (
    <div className="space-y-4" onKeyDown={handleKeyDown}>
      <ol className="flex flex-wrap items-center gap-x-2 gap-y-1.5 text-xs">
        {steps.map((s, i) => (
          <li
            key={s.id}
            aria-current={i === index ? "step" : undefined}
            className={cn(
              "flex items-center gap-1.5 rounded-full border px-2.5 py-1 font-medium transition",
              i === index
                ? "border-primary/50 bg-primary/10 text-primary"
                : i < index || onSummaryStep
                  ? "border-white/[0.08] bg-white/[0.03] text-muted-foreground"
                  : "border-white/[0.05] text-muted-foreground",
            )}
          >
            <span>{i + 1}.</span>
            <span>{s.title}</span>
          </li>
        ))}
        {summary && (
          <li
            aria-current={onSummaryStep ? "step" : undefined}
            className={cn(
              "flex items-center gap-1.5 rounded-full border px-2.5 py-1 font-medium transition",
              onSummaryStep
                ? "border-primary/50 bg-primary/10 text-primary"
                : "border-white/[0.05] text-muted-foreground",
            )}
          >
            <span>{steps.length + 1}.</span>
            <span>Review</span>
          </li>
        )}
      </ol>
      <p className="text-xs text-muted-foreground">
        Step {index + 1} of {totalSteps}
      </p>

      <h3
        ref={headingRef}
        tabIndex={-1}
        className="text-sm font-semibold text-foreground outline-none"
      >
        {onSummaryStep ? "Review" : step?.title}
      </h3>

      <div>{onSummaryStep ? summary?.(summaryState) : step?.render()}</div>

      {error && (
        <p role="alert" className="text-xs text-state-over">
          {error}
        </p>
      )}

      <div className="flex gap-2 pt-2">
        <Button onClick={goBack} disabled={index === 0}>
          Back
        </Button>
        {index < totalSteps - 1 ? (
          <Button tone="primary" onClick={goNext}>
            Next
          </Button>
        ) : (
          <Button
            tone="primary"
            onClick={() => void finish()}
            disabled={finishing}
          >
            Finish
          </Button>
        )}
        {onCancel && <Button onClick={onCancel}>Cancel</Button>}
      </div>
    </div>
  );
}
