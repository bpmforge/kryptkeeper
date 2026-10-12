import { useState } from "react";

export type BulkProgress = {
  done: number;
  total: number;
  errors: string[];
};

// Shared multi-select state for bulk-action tables (Certificates.tsx's
// selectedFingerprints pattern, generalized to any row id type).
export function useBulkSelection<T extends string>() {
  const [selected, setSelected] = useState<T[]>([]);

  const toggle = (id: T) => {
    setSelected((curr) =>
      curr.includes(id) ? curr.filter((x) => x !== id) : [...curr, id],
    );
  };

  const toggleAll = (ids: T[]) => {
    const allSelected =
      ids.length > 0 && ids.every((id) => selected.includes(id));
    setSelected(allSelected ? [] : [...ids]);
  };

  const clear = () => setSelected([]);

  return { selected, toggle, toggleAll, clear };
}

// Runs `action` for each id sequentially, reporting done/total/errors after
// every item so a caller can render a progress bar mid-run. Failures are
// collected per item rather than aborting the batch, so one bad row never
// hides the outcome of the rest.
export async function runBulkAction<T>(
  ids: T[],
  action: (id: T) => Promise<unknown>,
  onProgress: (progress: BulkProgress) => void,
): Promise<string[]> {
  const errors: string[] = [];
  onProgress({ done: 0, total: ids.length, errors: [] });
  for (let i = 0; i < ids.length; i++) {
    try {
      await action(ids[i]);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      errors.push(`${String(ids[i])} — ${msg}`);
    }
    onProgress({ done: i + 1, total: ids.length, errors: [...errors] });
  }
  return errors;
}
