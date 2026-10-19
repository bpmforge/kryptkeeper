import { useNavigate } from "react-router-dom";
import { AlertTriangle } from "lucide-react";
import {
  TRUST_CLASSES,
  TRUST_CLASS_CUE,
  TRUST_CLASS_LABEL,
  type TrustClass,
  type TrustClassCounts,
} from "../lib/trustClass";

// Colour means state: a class is only coloured when it is a finding. Managed
// and public are the healthy readings; self-signed / other private CAs /
// unknown need someone to decide whose they are.
const TONE: Record<TrustClass, string> = {
  managed: "text-state-auto",
  public: "text-primary",
  private_other: "text-state-attn",
  self_signed: "text-state-attn",
  unknown: "text-state-attn",
};

// Distinct certificates seen on the network by whose they are, hub-issued ones
// included (a managed cert served on two endpoints is one certificate). Each
// segment drills into the endpoints presenting that class -- not the discovered
// certificate inventory, which would exclude the managed ones. Chain
// intermediates and roots a server presented are not counted.
export function TrustBreakdown({ counts }: { counts: TrustClassCounts }) {
  const navigate = useNavigate();
  return (
    <div
      data-testid="trust-strip"
      role="group"
      aria-label="Certificates seen on the network by issuer"
      className="flex flex-wrap items-center gap-4 rounded-xl border border-border bg-background/60 px-4 py-3 text-sm"
    >
      <span className="text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground">
        Seen on the network by issuer
      </span>
      {TRUST_CLASSES.map((cls) => {
        const n = counts[cls] ?? 0;
        return (
          <button
            key={cls}
            type="button"
            data-testid={`trust-${cls}`}
            className={(n > 0 ? TONE[cls] : "text-muted-foreground") + " hover:underline"}
            onClick={() =>
              navigate(`/discovery?trust_class=${cls}`)
            }
          >
            {n} {TRUST_CLASS_LABEL[cls]}
            {n > 0 && TRUST_CLASS_CUE[cls].icon === "alert" && (
              <>
                <AlertTriangle
                  size={12}
                  className="ml-1 inline align-[-1px]"
                  aria-hidden="true"
                />
                <span className="sr-only"> {TRUST_CLASS_CUE[cls].text}</span>
              </>
            )}
          </button>
        );
      })}
    </div>
  );
}
