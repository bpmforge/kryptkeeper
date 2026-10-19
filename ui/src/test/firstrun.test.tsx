import { renderHook, waitFor, act } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: { userPrefs: vi.fn(), setUserPrefs: vi.fn(), cas: vi.fn() },
}));

import { api } from "../lib/api";
import { useFirstRun } from "../lib/firstrun";

const noCas = { data: { items: [], total: 0 } };

beforeEach(() => {
  localStorage.clear();
  vi.mocked(api.userPrefs).mockReset();
  vi.mocked(api.setUserPrefs).mockReset();
  vi.mocked(api.cas).mockReset();
  vi.mocked(api.cas).mockResolvedValue(noCas as never);
});

describe("useFirstRun (W33-03)", () => {
  it("server pref true + empty localStorage: not first run, mirror written", async () => {
    vi.mocked(api.userPrefs).mockResolvedValue({
      data: { onboarding_dismissed: true },
    } as never);
    const { result } = renderHook(() => useFirstRun());
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.isFirstRun).toBe(false);
    expect(localStorage.getItem("kk_onboarded")).toBe("1");
    expect(api.cas).not.toHaveBeenCalled();
  });

  it("prefs 500 + localStorage '1': not first run, no server call needed", async () => {
    localStorage.setItem("kk_onboarded", "1");
    vi.mocked(api.userPrefs).mockRejectedValue(new Error("500"));
    const { result } = renderHook(() => useFirstRun());
    expect(result.current.isFirstRun).toBe(false);
    expect(result.current.loading).toBe(false);
  });

  it("prefs 500 + no flag + zero CAs: first run", async () => {
    vi.mocked(api.userPrefs).mockRejectedValue(new Error("500"));
    const { result } = renderHook(() => useFirstRun());
    await waitFor(() => expect(result.current.isFirstRun).toBe(true));
  });

  it("CA list 500: fails closed (isFirstRun false)", async () => {
    vi.mocked(api.userPrefs).mockResolvedValue({
      data: { onboarding_dismissed: false },
    } as never);
    vi.mocked(api.cas).mockRejectedValue(new Error("500"));
    const { result } = renderHook(() => useFirstRun());
    await waitFor(() => expect(api.cas).toHaveBeenCalled());
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.isFirstRun).toBe(false);
  });

  it("dismiss() issues the PUT and survives a PUT rejection", async () => {
    vi.mocked(api.userPrefs).mockResolvedValue({
      data: { onboarding_dismissed: false },
    } as never);
    vi.mocked(api.setUserPrefs).mockRejectedValue(new Error("offline"));
    const { result } = renderHook(() => useFirstRun());
    await waitFor(() => expect(result.current.isFirstRun).toBe(true));
    act(() => result.current.dismiss());
    await waitFor(() =>
      expect(api.setUserPrefs).toHaveBeenCalledWith({
        onboarding_dismissed: true,
      }),
    );
    expect(localStorage.getItem("kk_onboarded")).toBe("1");
    await waitFor(() => expect(result.current.isFirstRun).toBe(false));
  });
});
