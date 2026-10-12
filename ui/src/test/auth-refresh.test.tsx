import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("sonner", () => ({
  toast: { success: vi.fn(), error: vi.fn() },
}));

import { toast } from "sonner";
import { api, __resetSessionExpiryForTests } from "../lib/api";

const API_BASE = "/api/v1";

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? "OK" : "Error",
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as Response;
}

function freshTokens(access: string, refresh: string) {
  return jsonResponse({
    data: {
      access_token: access,
      token_type: "Bearer",
      expires_in: 900,
      refresh_token: refresh,
      refresh_expires_in: 2592000,
    },
  });
}

describe("transparent access-token refresh", () => {
  beforeEach(() => {
    __resetSessionExpiryForTests();
    sessionStorage.clear();
    sessionStorage.setItem("kk_session", "1");
    sessionStorage.setItem("auth_token", "expired-access-token");
    sessionStorage.setItem("kk_refresh_token", "refresh-token-1");
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it("retries the original request once, with the newly issued token, after a 401-then-refresh cycle", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    fetchMock
      .mockResolvedValueOnce(jsonResponse({ message: "unauthorized" }, 401))
      .mockResolvedValueOnce(
        freshTokens("fresh-access-token", "refresh-token-2"),
      )
      .mockResolvedValueOnce(jsonResponse({ data: [{ id: "cert-1" }] }));

    const result = await api.certificates();

    expect(fetchMock).toHaveBeenCalledTimes(3);

    const [firstUrl] = fetchMock.mock.calls[0];
    const [refreshUrl, refreshInit] = fetchMock.mock.calls[1];
    const [retryUrl, retryInit] = fetchMock.mock.calls[2];

    expect(firstUrl).toBe(`${API_BASE}/certificates`);
    expect(refreshUrl).toBe(`${API_BASE}/auth/refresh`);
    expect(JSON.parse(refreshInit.body as string)).toEqual({
      refresh_token: "refresh-token-1",
    });

    // The retry must be a genuinely NEW request built from the refreshed
    // token, not the original request replayed with its stale Authorization
    // header -- that stale-retry bug would still pass a looser "called 3
    // times" assertion.
    expect(retryUrl).toBe(`${API_BASE}/certificates`);
    expect((retryInit.headers as Record<string, string>).Authorization).toBe(
      "Bearer fresh-access-token",
    );

    expect(result).toEqual({ data: [{ id: "cert-1" }] });

    expect(sessionStorage.getItem("auth_token")).toBe("fresh-access-token");
    expect(sessionStorage.getItem("kk_refresh_token")).toBe("refresh-token-2");
  });

  it("shares a single in-flight refresh across concurrent 401s (the refresh token is single-use server-side)", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    fetchMock
      .mockResolvedValueOnce(jsonResponse({ message: "unauthorized" }, 401)) // certificates -> 401
      .mockResolvedValueOnce(jsonResponse({ message: "unauthorized" }, 401)) // cas -> 401
      .mockResolvedValueOnce(
        freshTokens("fresh-access-token", "refresh-token-2"),
      ) // one shared refresh
      .mockResolvedValueOnce(jsonResponse({ data: [{ id: "cert-1" }] })) // certificates retry
      .mockResolvedValueOnce(jsonResponse({ data: [{ id: "ca-1" }] })); // cas retry

    const [certs, cas] = await Promise.all([api.certificates(), api.cas()]);

    const refreshCalls = fetchMock.mock.calls.filter(
      ([url]) => url === `${API_BASE}/auth/refresh`,
    );
    expect(refreshCalls).toHaveLength(1);
    expect(certs).toEqual({ data: [{ id: "cert-1" }] });
    expect(cas).toEqual({ data: [{ id: "ca-1" }] });
  });

  it("presents the rotated refresh token on a second cycle, not the one the server already consumed", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    fetchMock
      .mockResolvedValueOnce(jsonResponse({ message: "unauthorized" }, 401))
      .mockResolvedValueOnce(freshTokens("access-2", "refresh-2"))
      .mockResolvedValueOnce(jsonResponse({ data: [] }))
      .mockResolvedValueOnce(jsonResponse({ message: "unauthorized" }, 401))
      .mockResolvedValueOnce(freshTokens("access-3", "refresh-3"))
      .mockResolvedValueOnce(jsonResponse({ data: [] }));

    await api.certificates();
    await api.certificates();

    const refreshCalls = fetchMock.mock.calls.filter(
      ([url]) => url === `${API_BASE}/auth/refresh`,
    );
    expect(refreshCalls).toHaveLength(2);
    // auth.Refresh deletes refresh-token-1 the instant the first cycle
    // consumes it -- a second cycle that resent refresh-token-1 would fail
    // server-side. Only passing the newly-issued refresh-2 proves rotation
    // was actually persisted, not just accepted once.
    expect(JSON.parse(refreshCalls[1][1].body as string)).toEqual({
      refresh_token: "refresh-2",
    });
  });

  it("tells the user their session expired and sends them to /login when the refresh token is rejected", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const assignSpy = vi.fn();
    vi.stubGlobal("location", { ...window.location, assign: assignSpy });

    fetchMock
      .mockResolvedValueOnce(jsonResponse({ message: "unauthorized" }, 401))
      .mockResolvedValueOnce(
        jsonResponse({ message: "invalid refresh token" }, 401),
      );

    await expect(api.certificates()).rejects.toThrow();

    expect(toast.error).toHaveBeenCalledWith(
      expect.stringMatching(/session.*expired/i),
    );
    expect(assignSpy).toHaveBeenCalledWith("/login");
    expect(sessionStorage.getItem("auth_token")).toBeNull();
    expect(sessionStorage.getItem("kk_refresh_token")).toBeNull();
    expect(sessionStorage.getItem("kk_session")).toBeNull();
  });

  it("goes straight to the session-expired path when there is no refresh token to spend (e.g. an SSO-established session)", async () => {
    sessionStorage.removeItem("kk_refresh_token");
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const assignSpy = vi.fn();
    vi.stubGlobal("location", { ...window.location, assign: assignSpy });

    fetchMock.mockResolvedValueOnce(
      jsonResponse({ message: "unauthorized" }, 401),
    );

    await expect(api.certificates()).rejects.toThrow();

    // No refresh attempt was made -- there was nothing to send.
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(assignSpy).toHaveBeenCalledWith("/login");
  });

  it("never leaves the caller silently resolved on a failed refresh -- the promise rejects", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("location", { ...window.location, assign: vi.fn() });

    fetchMock
      .mockResolvedValueOnce(jsonResponse({ message: "unauthorized" }, 401))
      .mockResolvedValueOnce(jsonResponse({ message: "unauthorized" }, 401));

    await expect(api.certificates()).rejects.toThrow(/session/i);
  });
});

// --- S-59: transient failures preserve the session; expiry reaches the user ---

describe("refresh failure taxonomy (S-59)", () => {
  let assignSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    __resetSessionExpiryForTests();
    sessionStorage.clear();
    sessionStorage.setItem("kk_session", "1");
    sessionStorage.setItem("auth_token", "expired-access-token");
    sessionStorage.setItem("kk_refresh_token", "refresh-token-1");
    assignSpy = vi.fn();
    Object.defineProperty(window, "location", {
      value: { assign: assignSpy, pathname: "/" },
      writable: true,
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  it("preserves the session on a network-level refresh failure (offline/DNS/CORS)", async () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ message: "unauthorized" }, 401))
      .mockRejectedValueOnce(new TypeError("Failed to fetch"));

    await expect(api.certificates()).rejects.toThrow(/session was preserved/);

    // The 30-day credential is intact and nobody was logged out.
    expect(sessionStorage.getItem("kk_refresh_token")).toBe("refresh-token-1");
    expect(assignSpy).not.toHaveBeenCalled();
    // The two cases are distinguishable afterwards: a console error names
    // the transient cause.
    expect(consoleError).toHaveBeenCalledWith(
      expect.stringContaining("transient refresh failure (network)"),
      expect.anything(),
    );
  });

  it.each([[500], [502], [429]])(
    "preserves the session when the refresh endpoint answers %d",
    async (status) => {
      const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
      const fetchMock = vi.fn();
      vi.stubGlobal("fetch", fetchMock);
      fetchMock
        .mockResolvedValueOnce(jsonResponse({ message: "unauthorized" }, 401))
        .mockResolvedValueOnce(jsonResponse({ message: "boom" }, status));

      await expect(api.certificates()).rejects.toThrow(/session was preserved/);
      expect(sessionStorage.getItem("kk_refresh_token")).toBe("refresh-token-1");
      expect(assignSpy).not.toHaveBeenCalled();
      expect(consoleError).toHaveBeenCalledWith(
        expect.stringContaining(`HTTP ${status}`),
      );
    },
  );

  it("clears the session ONLY on a genuine 401 from the refresh endpoint, and the notice survives navigation", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ message: "unauthorized" }, 401))
      .mockResolvedValueOnce(jsonResponse({ message: "invalid refresh token" }, 401));

    await expect(api.certificates()).rejects.toThrow(/Session expired/);

    expect(sessionStorage.getItem("kk_refresh_token")).toBeNull();
    expect(assignSpy).toHaveBeenCalledWith("/login");
    // Stronger than "the toast mock was called": the notice is PERSISTED,
    // so it exists after the redirect tears the React tree (and the
    // <Toaster/>) down — which is how it actually reaches the user on the
    // Login page.
    expect(sessionStorage.getItem("kk_login_notice")).toMatch(/session has expired/i);
  });

  it("a burst of 401s after expiry produces one notice and one redirect", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    // Every request 401s; every refresh attempt 401s too.
    fetchMock.mockImplementation(() =>
      Promise.resolve(jsonResponse({ message: "unauthorized" }, 401)),
    );

    // Sequential bursts (the QueryClient-retry shape): each spends its own
    // refresh cycle because the first cleared the tokens.
    await expect(api.certificates()).rejects.toThrow();
    await expect(api.certificates()).rejects.toThrow();
    await expect(api.certificates()).rejects.toThrow();

    expect(assignSpy).toHaveBeenCalledTimes(1);
    expect(toast.error).toHaveBeenCalledTimes(1);
  });
});
