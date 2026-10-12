import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    testNotificationDelivery: vi.fn(),
    autoDerivePqcWaves: vi.fn(),
  },
}));

import { api } from "../lib/api";
import {
  expiredCertificatesPath,
  notifyOwnerTeam,
  openPqcWave,
  renewalPath,
} from "../lib/actions";

beforeEach(() => {
  vi.clearAllMocks();
});

describe("renewalPath", () => {
  it("filters the certificate workflow by the exact CA id", () => {
    expect(renewalPath("ca-7")).toBe("/certificates?ca_id=ca-7");
  });

  it("encodes CA ids that need it", () => {
    expect(renewalPath("ca a/b")).toBe("/certificates?ca_id=ca%20a%2Fb");
  });
});

describe("expiredCertificatesPath", () => {
  it("filters the certificate workflow to the expired status", () => {
    expect(expiredCertificatesPath()).toBe("/certificates?status=expired");
  });
});

describe("notifyOwnerTeam", () => {
  it("rejects an empty owner team without calling the API", async () => {
    const outcome = await notifyOwnerTeam("  ", "email", "owner@example.com");
    expect(outcome).toEqual({
      ok: false,
      message: "An owner team is required.",
    });
    expect(api.testNotificationDelivery).not.toHaveBeenCalled();
  });

  it("rejects an empty delivery target without calling the API", async () => {
    const outcome = await notifyOwnerTeam("platform-eng", "email", "   ");
    expect(outcome).toEqual({
      ok: false,
      message: "A delivery target is required.",
    });
    expect(api.testNotificationDelivery).not.toHaveBeenCalled();
  });

  it("sends a real delivery through the API on valid input", async () => {
    vi.mocked(api.testNotificationDelivery).mockResolvedValue({
      data: { delivery: { status: "sent" } },
    } as unknown as never);

    const outcome = await notifyOwnerTeam(
      "platform-eng",
      "slack",
      "owner@example.com",
    );

    expect(api.testNotificationDelivery).toHaveBeenCalledWith({
      channel: "slack",
      target: "owner@example.com",
      message:
        'Certificate expiry review requested for owner team "platform-eng".',
    });
    expect(outcome).toEqual({
      ok: true,
      message: "Notification sent to owner@example.com via slack.",
    });
  });

  it("surfaces an API failure instead of throwing", async () => {
    vi.mocked(api.testNotificationDelivery).mockRejectedValue(
      new Error("delivery backend unreachable"),
    );

    const outcome = await notifyOwnerTeam(
      "platform-eng",
      "email",
      "owner@example.com",
    );

    expect(outcome).toEqual({
      ok: false,
      message: "delivery backend unreachable",
    });
  });
});

describe("openPqcWave", () => {
  it("derives waves for real and reports how many are active", async () => {
    vi.mocked(api.autoDerivePqcWaves).mockResolvedValue({
      data: [{ id: "wave-1" }, { id: "wave-2" }],
    } as unknown as never);

    const outcome = await openPqcWave();

    expect(api.autoDerivePqcWaves).toHaveBeenCalled();
    expect(outcome).toEqual({
      ok: true,
      message: "PQC migration wave opened — 2 waves active.",
    });
  });

  it("surfaces an API failure instead of throwing", async () => {
    vi.mocked(api.autoDerivePqcWaves).mockRejectedValue(
      new Error("wave derivation failed"),
    );

    const outcome = await openPqcWave();

    expect(outcome).toEqual({
      ok: false,
      message: "wave derivation failed",
    });
  });
});
