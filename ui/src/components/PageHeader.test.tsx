import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { PageHeader } from "./PageHeader";

describe("PageHeader", () => {
  it("renders the eyebrow, title and description", () => {
    render(
      <PageHeader
        eyebrow="Inventory"
        title="Certificates"
        description="Search, filter, inspect, and act on certificate inventory."
      />,
    );

    expect(screen.getByText("Inventory")).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { level: 1, name: "Certificates" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "Search, filter, inspect, and act on certificate inventory.",
      ),
    ).toBeInTheDocument();
  });

  it("renders actions when the screen has page-level buttons", () => {
    render(
      <PageHeader
        eyebrow="Inventory"
        title="Certificates"
        description="…"
        actions={<button type="button">Issue certificate</button>}
      />,
    );

    expect(
      screen.getByRole("button", { name: "Issue certificate" }),
    ).toBeInTheDocument();
  });

  it("renders no action region when a screen has none", () => {
    const { container } = render(
      <PageHeader eyebrow="Trust" title="CAs" description="…" />,
    );

    expect(container.querySelectorAll("button")).toHaveLength(0);
  });

  // Type-level enforcement: eyebrow, title and description are all required,
  // and there is no icon/children/className prop to smuggle a fourth shape in.
  // These are compile-time checks — `npx tsc -b` in ui/ must pass with them
  // present and fail if any @ts-expect-error stops reproducing. The gate this
  // repo actually runs (`npm run lint` + `npm test -- --run`) does not
  // typecheck test files, so this is verified manually rather than by CI.
  it("is a closed shape at the type level (compile-time only, see comment above)", () => {
    // @ts-expect-error eyebrow is required
    PageHeader({ title: "x", description: "y" });
    // @ts-expect-error title is required
    PageHeader({ eyebrow: "x", description: "y" });
    // @ts-expect-error description is required
    PageHeader({ eyebrow: "x", title: "y" });
    // @ts-expect-error there is no icon prop — icon+H1 is not the rule
    PageHeader({ eyebrow: "x", title: "y", description: "z", icon: "w" });
    // @ts-expect-error there is no className escape hatch
    PageHeader({ eyebrow: "x", title: "y", description: "z", className: "w" });

    expect(true).toBe(true);
  });
});
