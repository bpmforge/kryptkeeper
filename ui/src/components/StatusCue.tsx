import { AlertTriangle, Check, Minus, X } from "lucide-react";
import { gradeCue, type StatusCue as Cue } from "../lib/trustClass";

const ICONS = { check: Check, alert: AlertTriangle, x: X, minus: Minus } as const;

// Icon plus visually hidden word so a status is never conveyed by colour alone.
export function StatusCueMark({ cue }: { cue: Cue }) {
  const Icon = ICONS[cue.icon];
  return (
    <>
      <Icon size={11} className="mr-1 shrink-0" aria-hidden="true" />
      <span className="sr-only">{cue.text}: </span>
    </>
  );
}

// Grade letter with its icon and text cue, for use inside a Badge.
export function GradeLabel({ grade }: { grade: string | undefined }) {
  return (
    <>
      <StatusCueMark cue={gradeCue(grade)} />
      {grade || "—"}
    </>
  );
}
