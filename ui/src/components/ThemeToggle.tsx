import { useTheme } from "next-themes";
import { Monitor, Moon, Sun } from "lucide-react";

// Three states, not two. "System" is a real choice — it means "follow the
// decision I already made for my whole machine", and a product that only
// offers light/dark quietly overrides that.
const OPTIONS = [
  { value: "light", label: "Light", Icon: Sun },
  { value: "dark", label: "Dark", Icon: Moon },
  { value: "system", label: "System", Icon: Monitor },
] as const;

export function ThemeToggle() {
  const { theme, setTheme } = useTheme();

  return (
    <div
      role="radiogroup"
      aria-label="Colour theme"
      className="inline-flex items-center gap-0.5 rounded-lg border border-border bg-card p-0.5"
    >
      {OPTIONS.map(({ value, label, Icon }) => {
        // `theme` is undefined until next-themes has read storage on the
        // client; treat that as "system" so nothing flickers to a
        // wrong-looking selection on first paint.
        const active = (theme ?? "system") === value;
        return (
          <button
            key={value}
            type="button"
            role="radio"
            aria-checked={active}
            aria-label={label}
            title={label}
            onClick={() => setTheme(value)}
            className={
              "flex h-7 w-7 items-center justify-center rounded-md transition-colors " +
              "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring " +
              (active
                ? "bg-secondary text-foreground"
                : "text-muted-foreground hover:text-foreground")
            }
          >
            <Icon size={14} aria-hidden="true" />
          </button>
        );
      })}
    </div>
  );
}
