import { useEffect, useRef, useState, type ReactNode } from "react";
import * as RadixDialog from "@radix-ui/react-dialog";
import { Menu, ShieldCheck, X } from "lucide-react";
import { useLocation } from "react-router-dom";

const DRAWER_ID = "mobile-nav-drawer";

/**
 * Below the md breakpoint the sidebar is replaced by a header menu button and a
 * drawer (WCAG 1.4.10 Reflow). Radix owns Escape, backdrop click, the focus trap,
 * moving focus in on open and returning it to the trigger on close. `children`
 * is the sidebar body, so desktop and drawer share one nav definition.
 */
export function MobileNav({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const { pathname } = useLocation();

  // Following a nav link (or any route change) dismisses the drawer.
  const [seenPath, setSeenPath] = useState(pathname);
  if (seenPath !== pathname) {
    setSeenPath(pathname);
    setOpen(false);
  }

  // If the viewport grows to md+ while open, the desktop sidebar takes over.
  useEffect(() => {
    if (!open || typeof window.matchMedia !== "function") return;
    const mq = window.matchMedia("(min-width: 48rem)");
    const onChange = (e: MediaQueryListEvent) => {
      if (e.matches) setOpen(false);
    };
    mq.addEventListener?.("change", onChange);
    return () => mq.removeEventListener?.("change", onChange);
  }, [open]);

  return (
    <>
      <header className="md:hidden sticky top-0 z-20 flex items-center gap-3 border-b border-border bg-[var(--surface-1)] px-3 py-2">
        <button
          ref={triggerRef}
          type="button"
          onClick={() => setOpen(true)}
          aria-label="Open navigation"
          aria-expanded={open}
          aria-controls={DRAWER_ID}
          className="flex h-11 w-11 items-center justify-center rounded-lg text-muted-foreground hover:bg-accent hover:text-foreground focus:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <Menu size={20} aria-hidden="true" />
        </button>
        <ShieldCheck size={16} className="text-primary" aria-hidden="true" />
        <span className="gradient-text font-bold text-base tracking-tight">
          Kryptkeeper
        </span>
      </header>
      <RadixDialog.Root open={open} onOpenChange={setOpen}>
        <RadixDialog.Portal>
          <RadixDialog.Overlay className="md:hidden fixed inset-0 z-40 bg-black/60 motion-safe:data-[state=open]:animate-in motion-safe:data-[state=closed]:animate-out motion-safe:data-[state=closed]:fade-out-0 motion-safe:data-[state=open]:fade-in-0" />
          <RadixDialog.Content
            id={DRAWER_ID}
            aria-describedby={undefined}
            onCloseAutoFocus={(e) => {
              // No Radix Trigger (the header sits outside the portal tree), so hand focus back by hand.
              e.preventDefault();
              triggerRef.current?.focus();
            }}
            className="md:hidden fixed inset-y-0 left-0 z-50 flex w-[min(280px,85vw)] flex-col border-r border-border bg-[var(--surface-1)] shadow-2xl outline-none motion-safe:data-[state=open]:animate-in motion-safe:data-[state=closed]:animate-out motion-safe:data-[state=closed]:slide-out-to-left motion-safe:data-[state=open]:slide-in-from-left"
          >
            <RadixDialog.Title className="sr-only">
              Navigation menu
            </RadixDialog.Title>
            <RadixDialog.Close asChild>
              <button
                type="button"
                aria-label="Close navigation"
                className="absolute right-2 top-3 z-10 flex h-11 w-11 items-center justify-center rounded-lg text-muted-foreground hover:bg-accent hover:text-foreground focus:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <X size={18} aria-hidden="true" />
              </button>
            </RadixDialog.Close>
            {children}
          </RadixDialog.Content>
        </RadixDialog.Portal>
      </RadixDialog.Root>
    </>
  );
}
