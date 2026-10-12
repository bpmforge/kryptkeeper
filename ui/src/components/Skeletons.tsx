import { Skeleton } from "@/components/ui/skeleton";

// ---------------------------------------------------------------------------
// Stat tile row — matches MetricCard / StatTile layouts
// ---------------------------------------------------------------------------
export function StatTilesSkeleton({ count = 6 }: { count?: number }) {
  return (
    <div
      className={`grid gap-3 ${count <= 3 ? "grid-cols-3" : "grid-cols-2 sm:grid-cols-3"}`}
    >
      {Array.from({ length: count }).map((_, i) => (
        <div
          key={i}
          className="rounded-2xl border border-white/[0.06] bg-[var(--surface-1)] p-5 space-y-3"
        >
          <Skeleton className="h-3 w-20 bg-white/[0.06]" />
          <Skeleton className="h-10 w-16 bg-white/[0.06]" />
          <Skeleton className="h-2 w-24 bg-white/[0.04]" />
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Panel with shimmer rows — for tables / lists inside a Panel
// ---------------------------------------------------------------------------
export function TableRowsSkeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-center gap-4">
          <Skeleton className="h-4 flex-1 bg-white/[0.06]" />
          <Skeleton className="h-4 w-24 bg-white/[0.06]" />
          <Skeleton className="h-4 w-16 bg-white/[0.06]" />
          <Skeleton className="h-5 w-14 rounded-full bg-white/[0.06]" />
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Dashboard skeleton
// ---------------------------------------------------------------------------
export function DashboardSkeleton() {
  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="space-y-2">
          <Skeleton className="h-7 w-64 bg-white/[0.06]" />
          <Skeleton className="h-4 w-40 bg-white/[0.04]" />
        </div>
        <Skeleton className="h-9 w-36 rounded-xl bg-white/[0.06]" />
      </div>
      {/* Stat tiles */}
      <StatTilesSkeleton count={6} />
      {/* Three panels */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {[1, 2, 3].map((i) => (
          <div
            key={i}
            className="rounded-2xl border border-white/[0.06] bg-[var(--surface-1)] p-5 space-y-4"
          >
            <Skeleton className="h-4 w-32 bg-white/[0.06]" />
            <div className="space-y-3">
              {Array.from({ length: 4 }).map((_, j) => (
                <Skeleton key={j} className="h-3 w-full bg-white/[0.04]" />
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Report page skeleton (stat tiles + table)
// ---------------------------------------------------------------------------
export function ReportSkeleton({
  tiles = 4,
  rows = 6,
}: {
  tiles?: number;
  rows?: number;
}) {
  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto">
      {/* Page header */}
      <div className="flex items-center gap-3">
        <Skeleton className="w-10 h-10 rounded-xl bg-white/[0.06]" />
        <div className="space-y-2">
          <Skeleton className="h-6 w-44 bg-white/[0.06]" />
          <Skeleton className="h-3 w-64 bg-white/[0.04]" />
        </div>
      </div>
      {/* Stat tiles */}
      <StatTilesSkeleton count={tiles} />
      {/* Table panel */}
      <div className="rounded-2xl border border-white/[0.06] bg-[var(--surface-1)] p-5 space-y-4">
        <div className="flex items-center justify-between">
          <Skeleton className="h-4 w-40 bg-white/[0.06]" />
          <Skeleton className="h-3 w-28 bg-white/[0.04]" />
        </div>
        <TableRowsSkeleton rows={rows} />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Keys page skeleton
// ---------------------------------------------------------------------------
export function KeysSkeleton() {
  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Skeleton className="w-10 h-10 rounded-xl bg-white/[0.06]" />
          <div className="space-y-2">
            <Skeleton className="h-6 w-40 bg-white/[0.06]" />
            <Skeleton className="h-3 w-56 bg-white/[0.04]" />
          </div>
        </div>
        <div className="flex gap-2">
          <Skeleton className="h-9 w-24 rounded-xl bg-white/[0.06]" />
          <Skeleton className="h-9 w-32 rounded-xl bg-white/[0.06]" />
        </div>
      </div>
      <div className="rounded-2xl border border-white/[0.06] bg-[var(--surface-1)] p-5 space-y-4">
        <Skeleton className="h-4 w-28 bg-white/[0.06]" />
        <TableRowsSkeleton rows={4} />
      </div>
    </div>
  );
}
