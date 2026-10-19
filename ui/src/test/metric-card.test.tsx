import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MetricCard } from "../components/ui";

describe("MetricCard accessible name", () => {
  it("reads label, value and hint as separate phrases", () => {
    render(<MetricCard label="Renewal threshold" value="30d" hint="trigger window before expiry" />);
    expect(
      screen.getByRole("button", { name: "Renewal threshold: 30d, trigger window before expiry" }),
    ).toBeInTheDocument();
  });
});
