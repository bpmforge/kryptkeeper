import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, NavLink } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

// The global setup replaces Radix Dialog with an inline stub; Escape, the focus trap
// and backdrop dismissal are exactly what is under test here, so use the real one.
vi.mock("@radix-ui/react-dialog", async () => vi.importActual("@radix-ui/react-dialog"));

import { MobileNav } from "../components/MobileNav";

function renderNav() {
  return render(
    <MemoryRouter initialEntries={["/"]}>
      <MobileNav>
        <nav aria-label="Main navigation">
          <NavLink to="/certificates">Certificates</NavLink>
          <NavLink to="/cas">CAs</NavLink>
        </nav>
      </MobileNav>
    </MemoryRouter>,
  );
}

const user = () => userEvent.setup({ pointerEventsCheck: 0 });

describe("MobileNav drawer", () => {
  it("is closed by default with a labelled, collapsed menu button", () => {
    renderNav();
    const btn = screen.getByRole("button", { name: "Open navigation" });
    expect(btn).toHaveAttribute("aria-expanded", "false");
    expect(btn).toHaveAttribute("aria-controls");
    expect(screen.queryByRole("navigation", { name: "Main navigation" })).toBeNull();
  });

  it("opens the drawer, moves focus inside, and marks the button expanded", async () => {
    const u = user();
    renderNav();
    const btn = screen.getByRole("button", { name: "Open navigation" });
    await u.click(btn);
    const dialog = await screen.findByRole("dialog", { name: "Navigation menu" });
    expect(btn).toHaveAttribute("aria-expanded", "true");
    expect(dialog.id).toBe(btn.getAttribute("aria-controls"));
    expect(screen.getByRole("navigation", { name: "Main navigation" })).toBeInTheDocument();
    await waitFor(() => expect(dialog.contains(document.activeElement)).toBe(true));
  });

  it("closes on Escape and returns focus to the menu button", async () => {
    const u = user();
    renderNav();
    const btn = screen.getByRole("button", { name: "Open navigation" });
    await u.click(btn);
    await screen.findByRole("dialog");
    await u.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(btn).toHaveFocus();
    expect(btn).toHaveAttribute("aria-expanded", "false");
  });

  it("closes on backdrop click", async () => {
    const u = user();
    const { baseElement } = renderNav();
    await u.click(screen.getByRole("button", { name: "Open navigation" }));
    await screen.findByRole("dialog");
    const overlay = baseElement.querySelector("[data-state='open'].fixed.inset-0");
    expect(overlay).not.toBeNull();
    await u.click(overlay as Element);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(screen.getByRole("button", { name: "Open navigation" })).toHaveFocus();
  });

  it("closes when a navigation link is followed", async () => {
    const u = user();
    renderNav();
    await u.click(screen.getByRole("button", { name: "Open navigation" }));
    await u.click(await screen.findByRole("link", { name: "Certificates" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("closes via the Close navigation button", async () => {
    const u = user();
    renderNav();
    await u.click(screen.getByRole("button", { name: "Open navigation" }));
    await u.click(await screen.findByRole("button", { name: "Close navigation" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });
});
