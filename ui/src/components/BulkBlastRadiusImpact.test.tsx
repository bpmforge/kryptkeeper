import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({ api: { blastRadius: vi.fn() } }));

import {
  BULK_PREVIEW_CAP,
  BulkBlastRadiusImpact,
  aggregateBlastRadius,
} from "./BlastRadiusImpact";
import { api } from "../lib/api";
import type { BlastRadiusResult } from "../lib/models";

function result(
  severity: BlastRadiusResult["severity"],
  services: string[],
): BlastRadiusResult {
  return {
    action: "revoke",
    target: "t",
    total_affected: services.length,
    severity,
    affected_by_kind: { service: services },
    graph_size: "1",
  };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("aggregateBlastRadius", () => {
  it("dedupes services, takes highest severity, counts failures", () => {
    const agg = aggregateBlastRadius([
      result("low", ["a", "b"]),
      result("high", ["b", "c"]),
      null,
      result("medium", []),
    ]);
    expect(agg.services.sort()).toEqual(["a", "b", "c"]);
    expect(agg.severity).toBe("high");
    expect(agg.failed).toBe(1);
    expect(agg.settled).toBe(4);
  });

  it("is none with no results", () => {
    expect(aggregateBlastRadius([]).severity).toBe("none");
  });
});

describe("BulkBlastRadiusImpact", () => {
  it("shows aggregate and reports done only after every preview settled", async () => {
    let release: (() => void) | undefined;
    vi.mocked(api.blastRadius).mockImplementation(async (_a, target) => {
      if (target === "fp2") await new Promise<void>((r) => (release = r));
      return {
        data: result(target === "fp2" ? "high" : "low", ["svc-1", target]),
      } as never;
    });
    const onStateChange = vi.fn();
    render(
      <BulkBlastRadiusImpact
        targets={["fp1", "fp2"]}
        onStateChange={onStateChange}
      />,
    );
    await waitFor(() => expect(api.blastRadius).toHaveBeenCalledTimes(2));
    expect(onStateChange).not.toHaveBeenCalledWith({ done: true, failed: 0 });
    expect(screen.getByRole("status")).toBeInTheDocument();
    release?.();
    expect(
      await screen.findByText("3 distinct services affected"),
    ).toBeInTheDocument();
    expect(screen.getByText("high")).toBeInTheDocument();
    // The done report is an effect after the render that shows the aggregate;
    // on a loaded runner it can land a tick later.
    await waitFor(() =>
      expect(onStateChange).toHaveBeenLastCalledWith({ done: true, failed: 0 }),
    );
  });

  it("caps at 50 targets with a message, and never exceeds 4 in flight", async () => {
    let inFlight = 0;
    let peak = 0;
    vi.mocked(api.blastRadius).mockImplementation(async () => {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 1));
      inFlight -= 1;
      return { data: result("none", []) } as never;
    });
    const targets = Array.from({ length: 60 }, (_, i) => `fp${i}`);
    const onStateChange = vi.fn();
    render(
      <BulkBlastRadiusImpact targets={targets} onStateChange={onStateChange} />,
    );
    expect(
      screen.getByText(
        "Blast radius preview covers the first 50 of 60 selected certificates.",
      ),
    ).toBeInTheDocument();
    await waitFor(() =>
      expect(onStateChange).toHaveBeenLastCalledWith({
        done: true,
        failed: 0,
      }),
    );
    expect(api.blastRadius).toHaveBeenCalledTimes(BULK_PREVIEW_CAP);
    expect(peak).toBeLessThanOrEqual(4);
  });

  it("counts failed previews, settles, and shows the count", async () => {
    vi.mocked(api.blastRadius).mockImplementation(async (_a, target) => {
      if (target === "bad") throw new Error("boom");
      return { data: result("low", ["s"]) } as never;
    });
    const onStateChange = vi.fn();
    render(
      <BulkBlastRadiusImpact
        targets={["ok", "bad"]}
        onStateChange={onStateChange}
      />,
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "1 of 2 previews failed",
    );
    expect(onStateChange).toHaveBeenLastCalledWith({ done: true, failed: 1 });
  });
});
