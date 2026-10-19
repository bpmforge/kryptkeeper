import { useEffect, useRef, useState } from "react";
import type { components } from "../generated/api-types";

export type OperationEvent = components["schemas"]["OperationEvent"];
export type OperationKind = OperationEvent["kind"];

export interface UseOperationEvents {
  live: boolean;
  latest: Record<string, OperationEvent>;
}

const API_BASE = import.meta.env.VITE_API_BASE || "/api/v1";
// A dropped connection (readyState CONNECTING) is retried by the browser,
// which re-sends Last-Event-ID itself; this caps how long we trust that.
const MAX_RECONNECTING_ERRORS = 3;
// A rejected connection (e.g. 429 at the per-principal stream cap) leaves
// EventSource CLOSED and the browser never retries it, so we re-open with
// exponential backoff. A fresh EventSource cannot carry Last-Event-ID, so
// callers resync via onResync.
const MAX_CLOSED_ERRORS = 6;
const BACKOFF_BASE_MS = 1_000;
const BACKOFF_MAX_MS = 30_000;

// EventSource cannot send Authorization/X-Tenant, which api.ts sets from
// these keys; when either is present the cookie fallback would be wrong.
function streamUsable(): boolean {
  if (typeof EventSource === "undefined") return false;
  try {
    return !(
      sessionStorage.getItem("kk_tenant") || sessionStorage.getItem("auth_token")
    );
  } catch {
    return true;
  }
}

export function useOperationEvents(opts?: {
  kinds?: OperationKind[];
  onEvent?: (e: OperationEvent) => void;
  onResync?: () => void;
}): UseOperationEvents {
  const [live, setLive] = useState(false);
  const [latest, setLatest] = useState<Record<string, OperationEvent>>({});
  const onEventRef = useRef(opts?.onEvent);
  const onResyncRef = useRef(opts?.onResync);
  const onEvent = opts?.onEvent;
  const onResync = opts?.onResync;
  useEffect(() => {
    onEventRef.current = onEvent;
    onResyncRef.current = onResync;
  });
  const kindsKey = opts?.kinds ? [...opts.kinds].sort().join(",") : "";

  useEffect(() => {
    if (!streamUsable()) return;
    const kinds = kindsKey ? new Set(kindsKey.split(",")) : null;
    let es: EventSource | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let disposed = false;
    let errors = 0;
    let reopened = false;

    const open = () => {
      const src = new EventSource(`${API_BASE}/events`, {
        withCredentials: true,
      });
      es = src;
      src.onopen = () => {
        errors = 0;
        setLive(true);
        if (reopened) {
          reopened = false;
          onResyncRef.current?.();
        }
      };
      src.onmessage = (m: MessageEvent) => {
        let ev: OperationEvent;
        try {
          ev = JSON.parse(String(m.data)) as OperationEvent;
        } catch {
          return;
        }
        if (!ev || typeof ev.op_id !== "string" || typeof ev.kind !== "string") {
          return;
        }
        if (kinds && !kinds.has(ev.kind)) return;
        setLatest((prev) => ({ ...prev, [ev.op_id]: ev }));
        onEventRef.current?.(ev);
      };
      src.onerror = () => {
        setLive(false);
        errors += 1;
        if (src.readyState === 2 /* CLOSED */) {
          src.close();
          if (disposed || errors >= MAX_CLOSED_ERRORS) return;
          const delay = Math.min(
            BACKOFF_BASE_MS * 2 ** (errors - 1),
            BACKOFF_MAX_MS,
          );
          timer = setTimeout(() => {
            reopened = true;
            open();
          }, delay);
          return;
        }
        if (errors >= MAX_RECONNECTING_ERRORS) src.close();
      };
    };
    open();

    return () => {
      disposed = true;
      if (timer) clearTimeout(timer);
      es?.close();
    };
  }, [kindsKey]);

  return { live, latest };
}
