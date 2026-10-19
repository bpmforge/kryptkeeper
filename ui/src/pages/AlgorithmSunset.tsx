import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { XCircle, Clock, CheckCircle2 } from "lucide-react";
import { api } from "../lib/api";
import type { AgilityRoadmapResult } from "../lib/api";
import { Badge, Button, Input, Panel, StateMessage } from "../components/ui";
import { PageHeader } from "../components/PageHeader";
import { ReportSkeleton } from "../components/Skeletons";
import type { components } from "../generated/api-types";

// S-39: this page used to declare its own SunsetData and reach it through an
// `as` cast, because api.ts typed the response Record<string, unknown>. The
// hand-written type said `sunset_summary` and `recommended`; the server sends
// `summary` and `recommended_replacement`. Nothing compared the two, so the
// page threw on every render and blanked the whole app.
//
// Both names now come from the spec, so a future rename fails the build here
// instead of at runtime. Every field is optional in the generated type, which
// is why the reads below are guarded rather than trusted.
type SunsetData = components["schemas"]["AlgorithmSunsetReport"];
type SunsetGroup = NonNullable<SunsetData["groups"]>[number];

function urgencyBadge(u: SunsetGroup["urgency"]) {
  if (u === "immediate") return <Badge tone="danger">Immediate</Badge>;
  if (u === "high") return <Badge tone="warning">High</Badge>;
  if (u === "medium") return <Badge tone="info">Medium</Badge>;
  return <Badge>Low</Badge>;
}

function statusIcon(s: SunsetGroup["status"]) {
  if (s === "banned") return <XCircle size={15} className="text-state-over" />;
  if (s === "sunset_2030")
    return <Clock size={15} className="text-state-attn" />;
  return <CheckCircle2 size={15} className="text-state-auto" />;
}

type RoadmapRow = NonNullable<
  NonNullable<AgilityRoadmapResult["roadmap"]>["by_wave"]
>[string][number];

const TIER_ORDER = ["Test", "Internal", "Customer-Facing"];
const ROW_CAP = 50;

function orderedTiers(byWave: Record<string, RoadmapRow[]>): string[] {
  const rest = Object.keys(byWave)
    .filter((k) => !TIER_ORDER.includes(k))
    .sort();
  return [...TIER_ORDER.filter((k) => k in byWave), ...rest];
}

function AgilityRoadmapPanel() {
  const navigate = useNavigate();
  const [name, setName] = useState("Algorithm transition");
  const [algorithms, setAlgorithms] = useState("");
  const [maxBits, setMaxBits] = useState("");
  const [deadline, setDeadline] = useState("");
  const [waveStatus, setWaveStatus] = useState("");
  const [waveError, setWaveError] = useState("");

  const derive = useMutation({
    mutationFn: () => {
      const bits = Number(maxBits);
      return api.cryptoAgilityRoadmap({
        name,
        algorithms: algorithms
          .split(",")
          .map((a) => a.trim())
          .filter(Boolean),
        max_key_bits: Number.isNaN(bits) ? 0 : bits,
        ...(deadline ? { deadline: `${deadline}T00:00:00Z` } : {}),
      });
    },
  });

  const createWave = useMutation({
    mutationFn: async (v: { tier: string; rows: RoadmapRow[] }) => {
      setWaveError("");
      const wave = await api.createPqcWave({
        name: `${name} - ${v.tier}`,
        ...(deadline ? { target_date: deadline } : {}),
      });
      const fps = v.rows.map((r) => r.fingerprint ?? "").filter(Boolean);
      for (let i = 0; i < fps.length; i++) {
        setWaveStatus(`Adding members ${i}/${fps.length}`);
        try {
          await api.addPqcWaveMember(wave.data.id, fps[i]);
        } catch (e) {
          throw new Error(
            `Wave ${wave.data.id} was created but adding members stopped at ${i + 1}/${fps.length}: ${(e as Error).message}. Finish in the PQC Migration page.`,
          );
        }
      }
      setWaveStatus(`Adding members ${fps.length}/${fps.length}`);
    },
    onSuccess: () => {
      toast.success("Migration wave created");
      navigate("/reports/pqc-migration");
    },
    onError: (e: Error) => {
      setWaveStatus("");
      setWaveError(e.message);
    },
  });

  const result = derive.data?.data;
  const progress = result?.progress;
  const byWave = result?.roadmap?.by_wave ?? {};
  const totalInventory = progress?.total_inventory ?? 0;
  const percent = progress?.percent_migrated ?? 0;
  const roadmapDeadline = result?.roadmap?.deadline ?? progress?.deadline;

  return (
    <Panel
      title="Crypto-agility roadmap"
      subtitle="Derive a tiered migration order for a policy, then hand a tier to the PQC wave flow."
    >
      <form
        className="grid gap-3 sm:grid-cols-2"
        onSubmit={(e) => {
          e.preventDefault();
          derive.mutate();
        }}
      >
        <label className="text-xs text-muted-foreground">
          Policy name
          <Input value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <label className="text-xs text-muted-foreground">
          Algorithms
          <Input
            value={algorithms}
            placeholder="RSA, ECDSA"
            onChange={(e) => setAlgorithms(e.target.value)}
          />
        </label>
        <label className="text-xs text-muted-foreground">
          Max key bits
          <Input
            type="number"
            value={maxBits}
            onChange={(e) => setMaxBits(e.target.value)}
          />
        </label>
        <label className="text-xs text-muted-foreground">
          Deadline
          <Input
            type="date"
            value={deadline}
            onChange={(e) => setDeadline(e.target.value)}
          />
        </label>
        <div className="sm:col-span-2 space-y-2">
          <Button type="submit" tone="primary" disabled={derive.isPending}>
            Derive roadmap
          </Button>
          <p className="text-xs text-muted-foreground">
            The roadmap plans waves toward post-quantum algorithms. To move a
            wave to a classical target such as ECDSA-P384, propose it from the
            CLI or API.
          </p>
        </div>
      </form>

      <div className="mt-4 space-y-4">
        {derive.error && (
          <StateMessage
            tone="error"
            title="Roadmap unavailable"
            message={(derive.error as Error).message}
          />
        )}
        {waveError && (
          <StateMessage
            tone="error"
            title="Wave not completed"
            message={waveError}
          />
        )}
        {waveStatus && (
          <p role="status" className="text-xs text-muted-foreground">
            {waveStatus}
          </p>
        )}

        {result && (
          <>
            <div className="space-y-1">
              <div className="flex items-center gap-2 flex-wrap">
                <span
                  role="progressbar"
                  aria-label="Percent migrated"
                  aria-valuenow={percent}
                  aria-valuemin={0}
                  aria-valuemax={100}
                  className="block h-2 w-48 rounded-full bg-muted overflow-hidden"
                >
                  <span
                    className="block h-full bg-primary"
                    style={{ width: `${Math.min(100, Math.max(0, percent))}%` }}
                  />
                </span>
                <span className="text-sm">
                  {`${percent}% migrated (${progress?.matched_remaining ?? 0} of ${totalInventory} remaining)`}
                </span>
                {progress?.overdue && <Badge tone="danger">Overdue</Badge>}
              </div>
              {roadmapDeadline && (
                <p className="text-xs text-muted-foreground">
                  Deadline: {new Date(roadmapDeadline).toLocaleDateString()}
                </p>
              )}
            </div>

            {(result.roadmap?.total_matched ?? 0) === 0 &&
              (totalInventory > 0 ? (
                <StateMessage
                  tone="success"
                  title="No active certificates match this policy"
                />
              ) : (
                <StateMessage title="Inventory is empty; nothing has been checked" />
              ))}

            {orderedTiers(byWave).map((tier) => {
              const rows = byWave[tier] ?? [];
              return (
                <section key={tier} aria-label={tier} className="space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <h3 className="text-sm font-semibold">{`${tier} (${rows.length})`}</h3>
                    <Button
                      aria-label={`Create wave from ${tier}`}
                      disabled={createWave.isPending || rows.length === 0}
                      onClick={() => createWave.mutate({ tier, rows })}
                    >
                      Create wave
                    </Button>
                  </div>
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="text-left text-muted-foreground">
                        <th className="py-1 pr-2">Common name</th>
                        <th className="py-1">Reason</th>
                      </tr>
                    </thead>
                    <tbody>
                      {rows.slice(0, ROW_CAP).map((r, i) => (
                        <tr key={r.fingerprint ?? i}>
                          <td className="py-1 pr-2">{r.common_name}</td>
                          <td className="py-1">{r.reason}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {rows.length > ROW_CAP && (
                    <p className="text-xs text-muted-foreground">
                      and {rows.length - ROW_CAP} more
                    </p>
                  )}
                </section>
              );
            })}
          </>
        )}
      </div>
    </Panel>
  );
}

export default function AlgorithmSunset() {
  const q = useQuery({
    queryKey: ["report-algorithm-sunset"],
    queryFn: api.algorithmSunset,
  });
  const report: SunsetData | undefined = q.data?.data;
  const summary = report?.summary;
  const groups = report?.groups ?? [];

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto fade-in-up">
      <PageHeader
        eyebrow="Reports"
        title="Algorithm Sunset"
        description="NIST 800-131A · CA/B Forum · CNSA 2.0 deprecation timeline."
      />

      {q.isLoading && <ReportSkeleton tiles={4} />}
      {q.error && (
        <StateMessage
          tone="error"
          title="Report unavailable"
          message={(q.error as Error).message}
        />
      )}

      {report && (
        <>
          {/* Summary */}
          <div className="grid grid-cols-3 gap-3">
            {[
              {
                label: "Banned Now",
                value: summary?.banned_now ?? 0,
                cls: "text-state-over",
                bg: "stat-rose",
              },
              {
                label: "Sunset 2030",
                value: summary?.sunset_2030 ?? 0,
                cls: "text-state-attn",
                bg: "stat-amber",
              },
              {
                label: "Compliant",
                value: summary?.compliant ?? 0,
                cls: "text-state-auto",
                bg: "stat-emerald",
              },
            ].map(({ label, value, cls, bg }) => (
              <div
                key={label}
                className={`glass rounded-2xl p-4 gradient-border ${value > 0 ? bg : ""}`}
              >
                <div className="text-xs text-muted-foreground uppercase tracking-widest mb-1">
                  {label}
                </div>
                <div className={`text-4xl font-black ${value > 0 ? cls : "text-foreground"} count-up`}>
                  {value}
                </div>
              </div>
            ))}
          </div>

          {groups.length === 0 &&
            ((summary?.compliant ?? 0) > 0 ? (
              <StateMessage
                tone="success"
                title="All algorithms compliant"
                message={`No certificates using deprecated or sunset algorithms across ${summary?.compliant} inventoried certificate${(summary?.compliant ?? 0) === 1 ? "" : "s"}.`}
              />
            ) : (
              // A green all-clear derived from an EMPTY inventory would be a
              // false assurance — nothing has been checked yet.
              <StateMessage
                title="Nothing inventoried yet"
                message="No certificates to assess. Issue or discover certificates first — then this page reports deprecated and sunset algorithms."
              />
            ))}

          {/* Groups */}
          <div className="space-y-4">
            {groups.map((g, i) => (
              <Panel key={g.algorithm ?? i}>
                <div className="flex items-start justify-between gap-4 flex-wrap">
                  <div className="flex items-start gap-3">
                    {statusIcon(g.status)}
                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-semibold text-foreground">
                          {g.algorithm ?? "Unknown algorithm"}
                        </span>
                        {urgencyBadge(g.urgency)}
                        <span className="text-xs text-muted-foreground">
                          {g.standard}
                        </span>
                      </div>
                      <p className="text-xs text-muted-foreground mt-1">
                        Deadline:{" "}
                        <span className="text-state-attn font-medium">
                          {g.deadline
                            ? new Date(g.deadline).toLocaleDateString()
                            : "—"}
                        </span>
                        {" · "}Recommended:{" "}
                        <span className="text-primary">
                          {g.recommended_replacement ?? "—"}
                        </span>
                      </p>
                      {(g.fingerprints?.length ?? 0) > 0 && (
                        <div className="mt-2 flex flex-wrap gap-1">
                          {g.fingerprints!.slice(0, 5).map((fp) => (
                            <Link
                              key={fp}
                              title={fp}
                              to={`/certificates/${fp}`}
                              className="inline-flex min-h-6 items-center font-mono text-[10px] text-muted-foreground bg-muted rounded px-1.5 py-0.5 truncate max-w-[140px] hover:text-primary"
                            >
                              {fp.slice(0, 16)}…
                            </Link>
                          ))}
                          {g.fingerprints!.length > 5 && (
                            <Link
                              to={`/certificates?sunset_group=${encodeURIComponent(g.id ?? "")}`}
                              className="inline-flex min-h-6 items-center text-xs text-primary hover:underline"
                            >
                              +{g.fingerprints!.length - 5} more — search the
                              inventory
                            </Link>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                  <div className="text-right shrink-0">
                    <div
                      className={`text-4xl font-black ${g.urgency === "immediate" ? "text-state-over" : g.urgency === "high" ? "text-state-attn" : "text-foreground"}`}
                    >
                      {g.count ?? 0}
                    </div>
                    <div className="text-xs text-muted-foreground">certificates</div>
                  </div>
                </div>
              </Panel>
            ))}
          </div>
        </>
      )}

      <AgilityRoadmapPanel />
    </div>
  );
}
