import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, render, renderHook, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider, useQuery, useQueryClient } from "@tanstack/react-query";
import { StrictMode, type ReactNode } from "react";
import { useOperationEvents, type OperationEvent } from "./useOperationEvents";

class FakeEventSource {
  static instances: FakeEventSource[] = [];
  url: string;
  withCredentials: boolean;
  readyState = 0;
  closed = false;
  onopen: (() => void) | null = null;
  onmessage: ((m: MessageEvent) => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(url: string, init?: { withCredentials?: boolean }) {
    this.url = url;
    this.withCredentials = !!init?.withCredentials;
    FakeEventSource.instances.push(this);
  }
  close() {
    this.closed = true;
    this.readyState = 2;
  }
  open() {
    this.readyState = 1;
    this.onopen?.();
  }
  emit(data: unknown, id?: string) {
    const raw = typeof data === "string" ? data : JSON.stringify(data);
    this.onmessage?.(new MessageEvent("message", { data: raw, lastEventId: id ?? "" }));
  }
  // Network drop: browser keeps the source CONNECTING and re-sends Last-Event-ID.
  fail() {
    this.readyState = 0;
    this.onerror?.();
  }
  // HTTP rejection (e.g. 429): browser gives up, readyState CLOSED.
  reject() {
    this.readyState = 2;
    this.onerror?.();
  }
}

// Shape taken from the OperationEvent schema in docs/openapi.yaml.
const ev = (
  op_id: string,
  kind: OperationEvent["kind"],
  status: OperationEvent["status"],
): OperationEvent => ({
  op_id,
  kind,
  status,
  progress: null,
  message: "",
  ts: "2026-10-16T10:00:00Z",
});

const last = () => FakeEventSource.instances[FakeEventSource.instances.length - 1];

beforeEach(() => {
  FakeEventSource.instances = [];
  sessionStorage.clear();
  vi.stubGlobal("EventSource", FakeEventSource);
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("useOperationEvents", () => {
  it("opens one EventSource at /api/v1/events with credentials", () => {
    const { result } = renderHook(() => useOperationEvents());
    expect(FakeEventSource.instances).toHaveLength(1);
    expect(last().url).toBe("/api/v1/events");
    expect(last().withCredentials).toBe(true);
    expect(result.current.live).toBe(false);
    act(() => last().open());
    expect(result.current.live).toBe(true);
  });

  it("leaves no second source after a StrictMode double-mount", () => {
    renderHook(() => useOperationEvents(), { wrapper: StrictMode });
    expect(FakeEventSource.instances.filter((s) => !s.closed)).toHaveLength(1);
  });

  it("stores latest event per op_id and filters by kinds", () => {
    const onEvent = vi.fn();
    const { result } = renderHook(() =>
      useOperationEvents({ kinds: ["scan"], onEvent }),
    );
    act(() => {
      last().open();
      last().emit(ev("a", "scan", "queued"), "1");
      last().emit(ev("a", "scan", "running"), "2");
      last().emit(ev("r", "renew", "running"), "3");
    });
    expect(result.current.latest.a.status).toBe("running");
    expect(result.current.latest.r).toBeUndefined();
    expect(onEvent).toHaveBeenCalledTimes(2);
  });

  it("ignores malformed frames", () => {
    const onEvent = vi.fn();
    const { result } = renderHook(() => useOperationEvents({ onEvent }));
    act(() => {
      last().emit("{not json");
      last().emit({ foo: 1 });
    });
    expect(onEvent).not.toHaveBeenCalled();
    expect(result.current.latest).toEqual({});
  });

  it("error then open returns live=true and keeps the same source (browser reconnect, Last-Event-ID is browser behaviour)", () => {
    const { result } = renderHook(() => useOperationEvents());
    const src = last();
    act(() => src.open());
    act(() => src.fail());
    expect(result.current.live).toBe(false);
    act(() => src.open());
    expect(result.current.live).toBe(true);
    expect(FakeEventSource.instances).toHaveLength(1);
    expect(src.closed).toBe(false);
  });

  it("falls back to polling after 3 consecutive errors: live=false, source closed", () => {
    const { result } = renderHook(() => useOperationEvents());
    const src = last();
    act(() => src.open());
    act(() => src.fail());
    act(() => src.fail());
    expect(src.closed).toBe(false);
    act(() => src.fail());
    expect(src.closed).toBe(true);
    expect(result.current.live).toBe(false);
    expect(FakeEventSource.instances).toHaveLength(1);
  });

  it("a successful open resets the consecutive error count", () => {
    renderHook(() => useOperationEvents());
    const src = last();
    act(() => src.fail());
    act(() => src.fail());
    act(() => src.open());
    act(() => src.fail());
    act(() => src.fail());
    expect(src.closed).toBe(false);
  });

  it("backs off exponentially after a 429 rejection, reopens, and resyncs", () => {
    vi.useFakeTimers();
    const onResync = vi.fn();
    const { result } = renderHook(() => useOperationEvents({ onResync }));
    const first = last();
    act(() => first.reject());
    expect(first.closed).toBe(true);
    expect(FakeEventSource.instances).toHaveLength(1);
    act(() => void vi.advanceTimersByTime(999));
    expect(FakeEventSource.instances).toHaveLength(1);
    act(() => void vi.advanceTimersByTime(1));
    expect(FakeEventSource.instances).toHaveLength(2);

    act(() => last().reject());
    act(() => void vi.advanceTimersByTime(1_999));
    expect(FakeEventSource.instances).toHaveLength(2);
    act(() => void vi.advanceTimersByTime(1));
    expect(FakeEventSource.instances).toHaveLength(3);

    act(() => last().open());
    expect(result.current.live).toBe(true);
    expect(onResync).toHaveBeenCalledTimes(1);
  });

  it("stops retrying a persistently rejected stream", () => {
    vi.useFakeTimers();
    renderHook(() => useOperationEvents());
    for (let i = 0; i < 10; i++) {
      act(() => last().reject());
      act(() => void vi.advanceTimersByTime(60_000));
    }
    expect(FakeEventSource.instances).toHaveLength(6);
  });

  it("closes the source and cancels a pending reopen on unmount", () => {
    vi.useFakeTimers();
    const { unmount } = renderHook(() => useOperationEvents());
    const src = last();
    unmount();
    expect(src.closed).toBe(true);

    const second = renderHook(() => useOperationEvents());
    act(() => last().reject());
    second.unmount();
    act(() => void vi.advanceTimersByTime(60_000));
    expect(FakeEventSource.instances).toHaveLength(2);
  });

  it("does not open a stream when kk_tenant is set", () => {
    sessionStorage.setItem("kk_tenant", "t1");
    const { result } = renderHook(() => useOperationEvents());
    expect(FakeEventSource.instances).toHaveLength(0);
    expect(result.current.live).toBe(false);
  });

  it("does not open a stream when auth_token is set", () => {
    sessionStorage.setItem("auth_token", "x");
    renderHook(() => useOperationEvents());
    expect(FakeEventSource.instances).toHaveLength(0);
  });

  it("does not throw when EventSource is undefined", () => {
    vi.stubGlobal("EventSource", undefined);
    const { result } = renderHook(() => useOperationEvents());
    expect(result.current.live).toBe(false);
  });
});

describe("scan polling replacement", () => {
  it("scan queued -> running -> completed re-renders within 2 s with 0 refetchInterval polls", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: false });
    let status: "queued" | "running" | "completed" = "queued";
    const fetchJobs = vi.fn(async () => [{ id: "job1", status }]);

    function Harness() {
      const qc = useQueryClient();
      const { live } = useOperationEvents({
        kinds: ["scan"],
        onEvent: () =>
          void qc.invalidateQueries({ queryKey: ["discovery-scan-jobs"] }),
      });
      const q = useQuery({
        queryKey: ["discovery-scan-jobs"],
        queryFn: fetchJobs,
        refetchInterval: (query) => {
          if (live) return false;
          const active = (query.state.data ?? []).some(
            (j) => j.status === "queued" || j.status === "running",
          );
          return active ? 4_000 : false;
        },
      });
      return <div data-testid="s">{q.data?.[0]?.status ?? "none"}</div>;
    }

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const wrapper = ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    );
    render(<Harness />, { wrapper });
    await act(async () => void (await vi.advanceTimersByTimeAsync(0)));
    expect(screen.getByTestId("s").textContent).toBe("queued");
    expect(fetchJobs).toHaveBeenCalledTimes(1);

    act(() => last().open());
    // Stream is live: the 4 s timer must not poll.
    await act(async () => void (await vi.advanceTimersByTimeAsync(12_000)));
    expect(fetchJobs).toHaveBeenCalledTimes(1);

    status = "running";
    act(() => last().emit(ev("job1", "scan", "running"), "1"));
    await act(async () => void (await vi.advanceTimersByTimeAsync(2_000)));
    expect(screen.getByTestId("s").textContent).toBe("running");
    expect(fetchJobs).toHaveBeenCalledTimes(2);

    status = "completed";
    act(() => last().emit(ev("job1", "scan", "completed"), "2"));
    await act(async () => void (await vi.advanceTimersByTimeAsync(2_000)));
    expect(screen.getByTestId("s").textContent).toBe("completed");
    expect(fetchJobs).toHaveBeenCalledTimes(3);
  });

  it("falls back to the 4 s poll when the stream is not live", async () => {
    vi.useFakeTimers();
    const fetchJobs = vi.fn(async () => [{ id: "j", status: "running" }]);
    function Harness() {
      const { live } = useOperationEvents({ kinds: ["scan"] });
      useQuery({
        queryKey: ["discovery-scan-jobs"],
        queryFn: fetchJobs,
        refetchInterval: live ? false : 4_000,
      });
      return null;
    }
    const qc = new QueryClient();
    render(
      <QueryClientProvider client={qc}>
        <Harness />
      </QueryClientProvider>,
    );
    await act(async () => void (await vi.advanceTimersByTimeAsync(0)));
    await act(async () => void (await vi.advanceTimersByTimeAsync(4_100)));
    expect(fetchJobs.mock.calls.length).toBeGreaterThanOrEqual(2);
  });
});
