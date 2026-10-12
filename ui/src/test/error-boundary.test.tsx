import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ErrorBoundary } from "../components/ErrorBoundary";

function Boom({ throws = true }: { throws?: boolean }) {
  if (throws) throw new Error("Cannot read properties of undefined");
  return <div>page content</div>;
}

// React itself logs caught render errors to console.error. Silence it so a
// passing run stays readable, but assert our own componentDidCatch still logs —
// swallowing the stack would trade a visible failure for an invisible one.
let errorSpy: ReturnType<typeof vi.spyOn>;
beforeEach(() => {
  errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => {
  errorSpy.mockRestore();
});

// S-41. The regression this locks down is S-39: one property read in one report
// page unmounted the router, the sidebar and the header, leaving a black
// rectangle. The page failing is a bug either way — what matters here is that
// everything around it keeps working.
describe("ErrorBoundary", () => {
  it("keeps the surrounding shell mounted when a page throws", () => {
    render(
      <div>
        <nav>sidebar</nav>
        <ErrorBoundary>
          <Boom />
        </ErrorBoundary>
      </div>,
    );

    // The shell is the whole point.
    expect(screen.getByText("sidebar")).toBeInTheDocument();
    expect(screen.getByText("This page failed to render")).toBeInTheDocument();
  });

  it("surfaces the underlying message rather than a blank panel", () => {
    render(
      <ErrorBoundary>
        <Boom />
      </ErrorBoundary>,
    );

    expect(
      screen.getByText(/Cannot read properties of undefined/),
    ).toBeInTheDocument();
  });

  it("still logs the failure for whoever has to debug it", () => {
    render(
      <ErrorBoundary>
        <Boom />
      </ErrorBoundary>,
    );

    expect(errorSpy).toHaveBeenCalledWith(
      "[ErrorBoundary] page render failed",
      expect.any(Error),
      expect.anything(),
    );
  });

  it("renders children untouched when nothing throws", () => {
    render(
      <ErrorBoundary>
        <Boom throws={false} />
      </ErrorBoundary>,
    );

    expect(screen.getByText("page content")).toBeInTheDocument();
    expect(
      screen.queryByText("This page failed to render"),
    ).not.toBeInTheDocument();
  });

  it("recovers when the cause is gone and Try again is pressed", async () => {
    function Flaky({ state }: { state: { fail: boolean } }) {
      if (state.fail) throw new Error("transient");
      return <div>recovered</div>;
    }
    const state = { fail: true };

    render(
      <ErrorBoundary>
        <Flaky state={state} />
      </ErrorBoundary>,
    );
    expect(screen.getByText("This page failed to render")).toBeInTheDocument();

    state.fail = false;
    await userEvent.click(screen.getByRole("button", { name: /try again/i }));

    expect(screen.getByText("recovered")).toBeInTheDocument();
  });
});
