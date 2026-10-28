import "@testing-library/jest-dom";
import { beforeEach, afterEach, vi } from "vitest";
import * as React from "react";
import { configure } from "@testing-library/react";

// findBy*/waitFor give up after 1 s by default. On a CI runner busy with
// parallel jobs a first render can take longer, and those timeouts failed
// unrelated PRs (a different test each run). Only the wait grows; no
// assertion changes.
configure({ asyncUtilTimeout: 5000 });

// Radix Dialog uses a portal + scroll lock that sets pointer-events:none on
// document.body, blocking userEvent clicks in jsdom. Replace it with a simple
// wrapper that renders inline (no portal, no scroll lock) during tests.
vi.mock("@radix-ui/react-dialog", () => {
  const Root = ({
    open,
    children,
  }: {
    open?: boolean;
    onOpenChange?: (o: boolean) => void;
    children: React.ReactNode;
  }) => (open ? React.createElement(React.Fragment, null, children) : null);

  const Portal = ({ children }: { children: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children);

  const Overlay = ({ className }: { className?: string }) =>
    React.createElement("div", { "data-testid": "dialog-overlay", className });

  const Content = ({
    children,
    ...props
  }: {
    children: React.ReactNode;
    [key: string]: unknown;
  }) =>
    React.createElement(
      "div",
      { role: "dialog", "aria-modal": "true", ...props },
      children,
    );

  const Title = ({
    children,
    className,
  }: {
    children: React.ReactNode;
    className?: string;
  }) => React.createElement("h2", { className }, children);

  const Description = ({
    children,
    className,
  }: {
    children: React.ReactNode;
    className?: string;
  }) => React.createElement("p", { className }, children);

  const Close = ({ children }: { children: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children);

  return { Root, Portal, Overlay, Content, Title, Description, Close };
});

beforeEach(() => {
  sessionStorage.setItem("kk_session", "1");
  sessionStorage.setItem("auth_token", "test-token"); // legacy compat
});

afterEach(() => {
  sessionStorage.clear();
});

// jsdom ships no matchMedia, and the app now genuinely asks the OS for a
// colour-scheme preference (next-themes, defaultTheme="system"). Without
// this every render that touches the theme throws. Defaults to light so a
// test that does not opt in gets a deterministic answer; a test wanting the
// dark branch can override matches per query.
if (typeof window !== "undefined" && !window.matchMedia) {
  window.matchMedia = ((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addEventListener: () => {},
    removeEventListener: () => {},
    addListener: () => {},
    removeListener: () => {},
    dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia;
}
