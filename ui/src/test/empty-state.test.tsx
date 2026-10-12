import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { EmptyState } from "../components/EmptyState";

describe("EmptyState", () => {
  it("offers the action that fills it, and calls onAction when triggered", async () => {
    const onAction = vi.fn();
    const user = userEvent.setup();
    render(
      <EmptyState
        title="No certificate authorities yet"
        description="A trust anchor is required before anything can be issued."
        actionLabel="Create your first CA"
        onAction={onAction}
      />,
    );

    expect(
      screen.getByText("No certificate authorities yet"),
    ).toBeInTheDocument();
    const action = screen.getByRole("button", {
      name: /create your first ca/i,
    });
    await user.click(action);
    expect(onAction).toHaveBeenCalledTimes(1);
  });

  it("renders no action when the caller does not provide one", () => {
    render(<EmptyState title="Nothing here" />);
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
