import { Copy } from "lucide-react";
import { toast } from "sonner";
import { Button, Dialog, Input } from "./ui";

// CopyButton writes `value` to the clipboard. Failure (no permission, no
// secure context) only toasts a generic message; the value is never logged.
export function CopyButton({ value, label }: { value: string; label: string }) {
  return (
    <Button
      aria-label={label}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          toast.success("Copied");
        } catch {
          toast.error("Copy failed; select the text and copy it manually");
        }
      }}
    >
      <Copy className="h-4 w-4" />
      Copy
    </Button>
  );
}

type SecretField = { label: string; value: string };

// SecretOnceDialog shows credentials the server returns exactly once. The
// values live only in the props of the caller's component state: the caller
// must clear that state in onDone so nothing outlives the dialog.
export function SecretOnceDialog({
  open,
  title,
  fields,
  onDone,
  children,
}: {
  open: boolean;
  title: string;
  fields: SecretField[];
  onDone: () => void;
  children?: React.ReactNode;
}) {
  return (
    <Dialog open={open} title={title} onClose={onDone} size="md">
      <div className="space-y-4">
        <p className="text-sm text-foreground">
          This secret is shown once and cannot be retrieved again
        </p>
        {fields.map((f) => (
          <div key={f.label} className="space-y-1">
            <label className="block text-xs text-muted-foreground">
              {f.label}
              <div className="mt-1 flex gap-2">
                <Input readOnly value={f.value} className="font-mono" />
                <CopyButton value={f.value} label={`Copy ${f.label}`} />
              </div>
            </label>
          </div>
        ))}
        {children}
        <div className="flex justify-end">
          <Button tone="primary" onClick={onDone}>
            Done
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
