import { Component, type ErrorInfo, type ReactNode } from "react";
import { Button, StateMessage } from "./ui";

// S-41. Before this existed, a render error anywhere in a routed page unmounted
// the entire tree — router, sidebar, header — leaving a black rectangle with no
// message and no way back. S-39 was one property read on one report page and it
// took the whole application down.
//
// A page that throws is a bug either way; the difference is whether the operator
// can still navigate, and whether they are told anything at all. Pages already
// handle *fetch* failure (a q.error branch rendering StateMessage). This is the
// case they cannot handle themselves: the throw happens during render, so the
// component that would show the message is the component that died.
//
// Mount this INSIDE the layout, never around it, or it defeats its own purpose.

type Props = {
  children: ReactNode;
  /** Rendered instead of the default panel. Mostly for tests. */
  fallback?: (error: Error, reset: () => void) => ReactNode;
};

type State = { error: Error | null };

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Keep the stack on the console: this is still a defect, and swallowing it
    // silently would trade a visible failure for an invisible one.
    console.error(
      "[ErrorBoundary] page render failed",
      error,
      info.componentStack,
    );
  }

  reset = () => this.setState({ error: null });

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    if (this.props.fallback) return this.props.fallback(error, this.reset);

    return (
      <div className="p-6 max-w-3xl mx-auto">
        <StateMessage
          tone="error"
          title="This page failed to render"
          message={
            error.message
              ? `${error.message} — the rest of the app still works; use the sidebar to continue.`
              : "The rest of the app still works; use the sidebar to continue."
          }
          action={
            <Button onClick={this.reset} tone="secondary">
              Try again
            </Button>
          }
        />
      </div>
    );
  }
}

export default ErrorBoundary;
