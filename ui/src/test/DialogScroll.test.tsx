import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { Button, Dialog } from "../components/ui";

describe("Dialog scrolls within the viewport (CB-01)", () => {
  it("caps its height, scrolls the body and keeps the footer outside the scroller", async () => {
    const onSubmit = vi.fn((e: React.FormEvent) => e.preventDefault());
    render(
      <Dialog
        open
        title="Tall dialog"
        onClose={() => {}}
        footer={
          <Button type="submit" form="tall-form">
            Create
          </Button>
        }
      >
        <form id="tall-form" onSubmit={onSubmit}>
          <input aria-label="Field" />
        </form>
      </Dialog>,
    );
    const dialog = screen.getByRole("dialog", { name: "Tall dialog" });
    expect(dialog.className).toContain("max-h-[calc(100dvh-2rem)]");
    const scroller = screen.getByLabelText("Field").closest("form")!.parentElement!;
    expect(scroller.className).toContain("overflow-y-auto");
    const create = screen.getByRole("button", { name: "Create" });
    expect(scroller.contains(create)).toBe(false);
    await userEvent.setup().click(create);
    expect(onSubmit).toHaveBeenCalledTimes(1);
  });
});
