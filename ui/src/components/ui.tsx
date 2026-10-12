// Shim layer: maps our legacy component API → shadcn/base-ui primitives.
// Pages import from this file unchanged; shadcn handles the rendering.
import { cva, type VariantProps } from "class-variance-authority";
import * as RadixDialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import type {
  InputHTMLAttributes,
  ReactNode,
  SelectHTMLAttributes,
  TextareaHTMLAttributes,
} from "react";
import { cn } from "@/lib/utils";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
export {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
export { Skeleton } from "@/components/ui/skeleton";

// ---------------------------------------------------------------------------
// formatDateTime — product-standard report timestamp (no raw toLocaleString)
// ---------------------------------------------------------------------------

// dateStyle/timeStyle drop seconds and lock the locale, so report headers
// don't leak a raw, CI-locale-dependent toLocaleString() render.
// eslint-disable-next-line react-refresh/only-export-components -- ui.tsx is the only shared file in this ticket's write_scope
export function formatDateTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(d);
}

// ---------------------------------------------------------------------------
// Panel — maps to shadcn Card with glass morphism overrides
// ---------------------------------------------------------------------------

type PanelProps = {
  title?: string;
  subtitle?: string;
  children: ReactNode;
  className?: string;
  accent?: boolean;
};

export function Panel({
  title,
  subtitle,
  children,
  className = "",
  accent = false,
}: PanelProps) {
  return (
    <Card
      className={cn(
        "rounded-2xl border border-white/[0.06] bg-[var(--surface-1)] shadow-sm gap-0",
        accent && "gradient-border",
        className,
      )}
    >
      {(title || subtitle) && (
        <CardHeader className="border-b border-white/[0.05] px-5 py-4">
          {title && (
            <CardTitle className="text-sm font-semibold tracking-wide text-foreground">
              {title}
            </CardTitle>
          )}
          {subtitle && (
            <CardDescription className="mt-0.5 text-xs text-muted-foreground">
              {subtitle}
            </CardDescription>
          )}
        </CardHeader>
      )}
      <CardContent className="px-5 py-4">{children}</CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Dialog — Radix UI portal (kept as-is; shadcn Dialog uses same Radix core)
// ---------------------------------------------------------------------------

type DialogProps = {
  open: boolean;
  title: string;
  description?: string;
  children: ReactNode;
  onClose: () => void;
  size?: "sm" | "md" | "lg";
};

const DIALOG_SIZE = { sm: "max-w-md", md: "max-w-2xl", lg: "max-w-4xl" };

export function Dialog({
  open,
  title,
  description,
  children,
  onClose,
  size = "md",
}: DialogProps) {
  return (
    <RadixDialog.Root
      open={open}
      onOpenChange={(o) => {
        if (!o) onClose();
      }}
    >
      <RadixDialog.Portal>
        <RadixDialog.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm pointer-events-auto data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0" />
        <RadixDialog.Content
          aria-label={title}
          className={`fixed left-1/2 top-1/2 z-50 w-full ${DIALOG_SIZE[size]} -translate-x-1/2 -translate-y-1/2 rounded-2xl border border-white/[0.08] bg-[var(--surface-1)] shadow-2xl shadow-black/40 outline-none pointer-events-auto data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 px-5 py-5`}
        >
          <div className="flex items-start justify-between gap-4 border-b border-white/[0.06] pb-4 mb-5">
            <div>
              <RadixDialog.Title className="text-base font-semibold text-foreground">
                {title}
              </RadixDialog.Title>
              {description ? (
                <RadixDialog.Description className="mt-1 text-xs text-muted-foreground leading-relaxed">
                  {description}
                </RadixDialog.Description>
              ) : null}
            </div>
            <RadixDialog.Close asChild>
              <button
                type="button"
                className="rounded-lg p-1.5 text-muted-foreground hover:text-foreground hover:bg-white/5 transition focus:outline-none focus:ring-2 focus:ring-ring"
                aria-label="Close dialog"
              >
                <X size={15} />
              </button>
            </RadixDialog.Close>
          </div>
          {children}
        </RadixDialog.Content>
      </RadixDialog.Portal>
    </RadixDialog.Root>
  );
}

// ---------------------------------------------------------------------------
// StateMessage
// ---------------------------------------------------------------------------

type StateMessageProps = {
  title: string;
  message?: string;
  tone?: "neutral" | "error" | "success";
  action?: ReactNode;
};

export function StateMessage({
  title,
  message,
  tone = "neutral",
  action,
}: StateMessageProps) {
  const toneClass =
    tone === "error"
      ? "border-state-over/50 bg-state-over/10 text-state-over"
      : tone === "success"
        ? "border-state-auto/50 bg-state-auto/10 text-state-auto"
        : "border-border bg-[var(--surface-2)] text-foreground";
  const role = tone === "error" ? "alert" : "status";
  const live = tone === "error" ? "assertive" : "polite";
  return (
    <div
      role={role}
      aria-live={live}
      className={`rounded-xl border px-4 py-3.5 ${toneClass}`}
    >
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <p className="text-sm font-semibold">{title}</p>
          {message ? (
            <p className="mt-0.5 text-xs text-muted-foreground">{message}</p>
          ) : null}
        </div>
        {action ? <div className="shrink-0">{action}</div> : null}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// MetricCard — gradient stat tile
// ---------------------------------------------------------------------------

type MetricCardProps = {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: "neutral" | "warning" | "danger" | "success" | "info";
  onClick?: () => void;
};

const METRIC_TONE = {
  neutral: { value: "text-foreground", tile: "" },
  warning: { value: "text-state-attn", tile: "stat-amber" },
  danger: { value: "text-state-over", tile: "stat-rose" },
  success: { value: "text-state-auto", tile: "stat-emerald" },
  info: { value: "text-primary", tile: "stat-cyan" },
};

export function MetricCard({
  label,
  value,
  hint,
  tone = "neutral",
  onClick,
}: MetricCardProps) {
  const t = METRIC_TONE[tone];
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-2xl border border-white/[0.06] bg-[var(--surface-1)] p-5 text-left transition hover:border-primary/25 hover:bg-[var(--surface-2)] focus:outline-none focus:ring-2 focus:ring-ring/50 ${t.tile}`}
    >
      <div className="text-[11px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">
        {label}
      </div>
      <div className={`mt-3 text-4xl font-black ${t.value}`}>{value}</div>
      {hint ? (
        <div className="mt-1.5 text-xs text-muted-foreground">{hint}</div>
      ) : null}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Badge — tone-mapped using shadcn-compatible class names
// ---------------------------------------------------------------------------

type BadgeProps = {
  children: ReactNode;
  tone?: "neutral" | "warning" | "danger" | "success" | "info";
};

export function Badge({ children, tone = "neutral" }: BadgeProps) {
  const toneClass =
    tone === "warning"
      ? "bg-state-attn/10 text-state-attn border-state-attn/50"
      : tone === "danger"
        ? "bg-state-over/10 text-state-over border-state-over/50"
        : tone === "success"
          ? "bg-state-auto/10 text-state-auto border-state-auto/50"
          : tone === "info"
            ? "bg-primary/10 text-primary border-primary/50"
            : "bg-muted/80 text-foreground border-border/50";
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium",
        toneClass,
      )}
    >
      {children}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Button — CVA variants
// ---------------------------------------------------------------------------

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-1.5 rounded-xl px-3.5 py-2 text-sm font-medium transition focus:outline-none focus:ring-2 focus:ring-ring/60 disabled:cursor-not-allowed disabled:opacity-40",
  {
    variants: {
      tone: {
        primary:
          "bg-gradient-to-b from-primary to-primary text-primary-foreground font-semibold hover:from-primary hover:to-primary shadow-sm shadow-cyan-900/20",
        secondary:
          "border border-white/[0.08] bg-white/[0.04] text-foreground hover:bg-white/[0.08] hover:text-white",
        danger:
          "bg-gradient-to-b from-state-over to-state-over text-white hover:from-state-over hover:to-state-over",
        ghost: "text-muted-foreground hover:text-foreground hover:bg-white/[0.05]",
      },
    },
    defaultVariants: { tone: "secondary" },
  },
);

type ButtonProps = {
  children: ReactNode;
  onClick?: () => void;
  tone?: "primary" | "secondary" | "danger" | "ghost";
  type?: "button" | "submit";
  disabled?: boolean;
  "aria-label"?: string;
} & VariantProps<typeof buttonVariants>;

export function Button({
  children,
  onClick,
  tone = "secondary",
  type = "button",
  disabled,
  "aria-label": ariaLabel,
}: ButtonProps) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      aria-label={ariaLabel}
      className={buttonVariants({ tone })}
    >
      {children}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Input / Textarea / Select / SectionLabel
// ---------------------------------------------------------------------------

const fieldBase =
  "w-full rounded-xl border border-white/[0.08] bg-[var(--surface-0)] px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring/60 transition";

type InputProps = InputHTMLAttributes<HTMLInputElement>;
export function Input({ className = "", ...props }: InputProps) {
  return <input {...props} className={cn(fieldBase, className)} />;
}

type TextareaProps = TextareaHTMLAttributes<HTMLTextAreaElement>;
export function Textarea({ className = "", ...props }: TextareaProps) {
  return (
    <textarea {...props} className={cn(fieldBase, "resize-none", className)} />
  );
}

type SelectProps = SelectHTMLAttributes<HTMLSelectElement>;
export function Select({ className = "", ...props }: SelectProps) {
  return (
    <select {...props} className={cn(fieldBase, "cursor-pointer", className)} />
  );
}

export function SectionLabel({ children }: { children: ReactNode }) {
  return (
    <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
      {children}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Divider
// ---------------------------------------------------------------------------
export function Divider() {
  return <hr className="border-white/[0.06]" />;
}
