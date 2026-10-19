import { useState } from "react";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { Dialog } from "../components/ui";

function Harness() {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button type="button" onClick={() => setOpen(true)}>
        Open it
      </button>
      <Dialog open={open} title="Sample dialog" onClose={() => setOpen(false)}>
        <input aria-label="Inside" />
      </Dialog>
    </>
  );
}

describe("Dialog focus return (WCAG 2.4.3)", () => {
  it("Escape closes the dialog and focus goes back to the control that opened it", async () => {
    const user = userEvent.setup();
    render(<Harness />);

    const opener = screen.getByRole("button", { name: "Open it" });
    opener.focus();
    await user.keyboard("{Enter}");
    expect(screen.getByRole("dialog", { name: "Sample dialog" })).toBeInTheDocument();

    await user.keyboard("{Escape}");
    // jsdom keeps the exiting node mounted (no animationend), so assert on focus, the behaviour under test.
    await waitFor(() => expect(opener).toHaveFocus());
  });
});
