import { useEffect, useState } from "react";
import { api } from "./api";
import { extractList } from "./models";
import type { CaRecord } from "./models";

const STORAGE_KEY = "kk_onboarded";

// -1 means "checked, but the fetch errored" -- distinct from null (not yet
// checked) and 0 (a real, empty CA list). Keeps isFirstRun fail-closed on an
// API error without leaving `loading` stuck true forever.
const UNKNOWN_ERRORED = -1;

// useFirstRun detects a fresh, unconfigured hub: zero CAs and the onboarding
// flow hasn't been dismissed. Fails closed on an API error (isFirstRun false
// rather than trapping an admin in onboarding when the real problem is an
// unreachable backend). caCount stays null until the fetch settles --
// "loading" is derived from that, not tracked as separate effect-set state,
// so the effect only ever calls setCaCount, and only from inside the async
// .then/.catch callbacks, never synchronously in the effect body itself
// (react-hooks/set-state-in-effect).
export function useFirstRun(): {
  isFirstRun: boolean;
  loading: boolean;
  dismiss: () => void;
} {
  const [dismissed, setDismissed] = useState(
    () => localStorage.getItem(STORAGE_KEY) === "1",
  );
  const [caCount, setCaCount] = useState<number | null>(null);

  useEffect(() => {
    if (dismissed) return;
    let cancelled = false;
    api
      .cas({ limit: 1 })
      .then((res) => {
        if (!cancelled) setCaCount(extractList<CaRecord>(res.data).length);
      })
      .catch(() => {
        if (!cancelled) setCaCount(UNKNOWN_ERRORED);
      });
    return () => {
      cancelled = true;
    };
  }, [dismissed]);

  const dismiss = () => {
    localStorage.setItem(STORAGE_KEY, "1");
    setDismissed(true);
  };

  return {
    isFirstRun: !dismissed && caCount === 0,
    loading: !dismissed && caCount === null,
    dismiss,
  };
}
