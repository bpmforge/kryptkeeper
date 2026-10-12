import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ThemeProvider } from "next-themes";
import { ThemeToggle } from "./ThemeToggle";

function renderToggle() {
  return render(
    <ThemeProvider attribute="class" defaultTheme="system" enableSystem>
      <ThemeToggle />
    </ThemeProvider>,
  );
}

describe("ThemeToggle", () => {
  it("offers light, dark and system — system is a real choice, not a fallback", () => {
    renderToggle();
    for (const label of ["Light", "Dark", "System"]) {
      expect(screen.getByRole("radio", { name: label })).toBeInTheDocument();
    }
  });

  it("defaults to following the operating system", () => {
    renderToggle();
    expect(screen.getByRole("radio", { name: "System" })).toBeChecked();
  });

  it("applies the chosen theme to the document and remembers it", async () => {
    const user = userEvent.setup();
    renderToggle();

    await user.click(screen.getByRole("radio", { name: "Dark" }));
    expect(document.documentElement).toHaveClass("dark");
    expect(screen.getByRole("radio", { name: "Dark" })).toBeChecked();

    await user.click(screen.getByRole("radio", { name: "Light" }));
    expect(document.documentElement).not.toHaveClass("dark");

    // The choice has to survive a reload, or it is not a preference.
    expect(localStorage.getItem("theme")).toBe("light");
  });

  it("exposes the control to assistive tech as a single labelled group", () => {
    renderToggle();
    expect(screen.getByRole("radiogroup", { name: "Colour theme" })).toBeInTheDocument();
  });
});
