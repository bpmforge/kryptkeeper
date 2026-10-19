import { useId, useState, type FormEvent } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { BlastRadiusAction, BlastRadiusResult } from "../lib/models";
import { Button, Input, Panel, Select } from "../components/ui";
import { PageHeader } from "../components/PageHeader";
import { BlastRadiusImpact } from "../components/BlastRadiusImpact";

// W31-18 adds edge_coverage to the wire shape; models.ts is out of this
// ticket's scope, so the page widens the type locally.
type BlastRadiusWithCoverage = BlastRadiusResult & {
  edge_coverage?: {
    certs_total: number;
    certs_with_ca_edge: number;
    certs_with_service_edge: number;
    basis: string;
  };
};

const ACTIONS: { value: BlastRadiusAction; label: string; hint: string }[] = [
  {
    value: "revoke",
    label: "Revoke certificate",
    hint: "SHA-256 fingerprint of the certificate",
  },
  { value: "retire_ca", label: "Retire CA", hint: "CA id" },
  {
    value: "deprecate_algorithm",
    label: "Deprecate algorithm",
    hint: "Algorithm and size, e.g. RSA-2048",
  },
];

const KIND_LABELS: Record<string, string> = {
  cert: "Certificates",
  service: "Services",
  ca: "CAs",
  key: "Keys",
  endpoint: "Endpoints",
};

const MAX_GRAPH_NODES = 40;
const ROW_H = 22;
const TOP = 30;
const WIDTH = 760;
const COL = { target: 12, cert: 270, service: 520 };

function severityClass(s: BlastRadiusResult["severity"]) {
  if (s === "high" || s === "critical") return "text-state-over";
  if (s === "medium") return "text-state-attn";
  return "text-state-auto";
}

function shorten(s: string) {
  return s.length > 28 ? `${s.slice(0, 27)}…` : s;
}

function DependencyGraph({
  action,
  target,
  severity,
  certs,
  services,
  describedBy,
}: {
  action: string;
  target: string;
  severity: BlastRadiusResult["severity"];
  certs: string[];
  services: string[];
  describedBy: string;
}) {
  const shownCerts = certs.slice(0, MAX_GRAPH_NODES);
  const shownServices = services.slice(0, MAX_GRAPH_NODES);
  const certMore = certs.length - shownCerts.length;
  const svcMore = services.length - shownServices.length;
  const rows = Math.max(
    shownCerts.length + (certMore > 0 ? 1 : 0),
    shownServices.length + (svcMore > 0 ? 1 : 0),
    1,
  );
  const height = TOP + rows * ROW_H + 10;
  const midY = TOP + (rows * ROW_H) / 2;
  const rowY = (i: number) => TOP + i * ROW_H + ROW_H / 2;
  const tone = severityClass(severity);
  return (
    <svg
      role="img"
      aria-label={`Dependency graph for ${action} ${target}: ${certs.length} certificates, ${services.length} services`}
      aria-describedby={describedBy}
      viewBox={`0 0 ${WIDTH} ${height}`}
      className="w-full h-auto"
    >
      <g className="text-muted-foreground" fill="currentColor" fontSize="11">
        <text x={COL.target} y={16}>
          Target
        </text>
        <text x={COL.cert} y={16}>
          Certificates
        </text>
        <text x={COL.service} y={16}>
          Services
        </text>
      </g>
      <g className={tone} fill="currentColor" fontSize="12">
        <text x={COL.target} y={midY + 4}>
          {shorten(target)}
        </text>
      </g>
      <g className={tone} stroke="currentColor" strokeWidth="1" fill="none">
        {shownCerts.map((id, i) => (
          <line
            key={`e-${id}`}
            x1={COL.target + 150}
            y1={midY}
            x2={COL.cert - 6}
            y2={rowY(i)}
          />
        ))}
      </g>
      {shownCerts.length > 0 && shownServices.length > 0 ? (
        <g
          className="text-muted-foreground"
          stroke="currentColor"
          strokeWidth="1"
          strokeDasharray="4 3"
        >
          <line
            x1={COL.cert + 200}
            y1={midY}
            x2={COL.service - 6}
            y2={midY}
          />
        </g>
      ) : null}
      <g fill="currentColor" fontSize="11" className="text-foreground">
        {shownCerts.map((id, i) => (
          <text key={`c-${id}`} x={COL.cert} y={rowY(i) + 4}>
            {shorten(id)}
          </text>
        ))}
        {certMore > 0 ? (
          <text x={COL.cert} y={rowY(shownCerts.length) + 4}>
            {`+${certMore} more`}
          </text>
        ) : null}
        {shownServices.map((id, i) => (
          <text key={`s-${id}`} x={COL.service} y={rowY(i) + 4}>
            {shorten(id)}
          </text>
        ))}
        {svcMore > 0 ? (
          <text x={COL.service} y={rowY(shownServices.length) + 4}>
            {`+${svcMore} more`}
          </text>
        ) : null}
      </g>
    </svg>
  );
}

export default function BlastRadius() {
  const uid = useId();
  const [action, setAction] = useState<BlastRadiusAction>("revoke");
  const [target, setTarget] = useState("");
  const [emptyError, setEmptyError] = useState(false);
  const [submitted, setSubmitted] = useState<{
    action: BlastRadiusAction;
    target: string;
  } | null>(null);

  const q = useQuery({
    queryKey: ["blast-radius", submitted?.action, submitted?.target],
    queryFn: () =>
      api.blastRadius(
        submitted?.action as BlastRadiusAction,
        submitted?.target as string,
      ),
    enabled: submitted !== null,
    retry: false,
    staleTime: 0,
  });

  const actionMeta = ACTIONS.find((a) => a.value === action) ?? ACTIONS[0];
  const actionId = `${uid}-action`;
  const targetId = `${uid}-target`;
  const hintId = `${uid}-hint`;
  const textId = `${uid}-impacted-text`;

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    const t = target.trim();
    if (t === "") {
      setEmptyError(true);
      return;
    }
    setEmptyError(false);
    setSubmitted({ action, target: t });
  }

  const result = q.data?.data as BlastRadiusWithCoverage | undefined;
  const showResult =
    submitted !== null && result !== undefined && result.total_affected > 0;
  const kinds = result ? Object.keys(result.affected_by_kind ?? {}) : [];
  const certs = result?.affected_by_kind?.cert ?? [];
  const services = result?.affected_by_kind?.service ?? [];
  const otherKinds = kinds.filter(
    (k) => k !== "cert" && k !== "service" && result?.affected_by_kind[k]?.length,
  );
  const cov = result?.edge_coverage;

  return (
    <div className="p-6 space-y-6 fade-in-up">
      <PageHeader
        eyebrow="Analysis"
        title="Blast Radius"
        description="See what breaks before you revoke a certificate, retire a CA or disallow an algorithm."
      />

      <Panel>
        <form onSubmit={onSubmit} className="grid gap-4 sm:grid-cols-[14rem_1fr_auto] items-start">
          <div className="space-y-1">
            <label htmlFor={actionId} className="text-sm font-medium">
              Action
            </label>
            <Select
              id={actionId}
              value={action}
              onChange={(e) => setAction(e.target.value as BlastRadiusAction)}
            >
              {ACTIONS.map((a) => (
                <option key={a.value} value={a.value}>
                  {a.label}
                </option>
              ))}
            </Select>
          </div>
          <div className="space-y-1">
            <label htmlFor={targetId} className="text-sm font-medium">
              Target
            </label>
            <Input
              id={targetId}
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder={actionMeta.hint}
              aria-describedby={hintId}
              aria-invalid={emptyError || undefined}
            />
            <p id={hintId} className="text-xs text-muted-foreground">
              {actionMeta.hint}
            </p>
          </div>
          <div className="pt-6">
            <Button type="submit" tone="primary">
              Simulate
            </Button>
          </div>
        </form>
        {emptyError ? (
          <p role="alert" className="mt-3 text-sm text-state-over">
            Enter a target to simulate.
          </p>
        ) : null}
      </Panel>

      {submitted ? (
        <Panel>
          <BlastRadiusImpact
            action={submitted.action}
            target={submitted.target}
          />
        </Panel>
      ) : null}

      {showResult && result && submitted ? (
        <Panel>
          <div className="space-y-4">
            <DependencyGraph
              action={submitted.action}
              target={submitted.target}
              severity={result.severity}
              certs={certs}
              services={services}
              describedBy={textId}
            />
            <section id={textId} aria-label="Impacted items (text)" className="space-y-3">
              <h3 className="text-sm font-semibold">Certificates ({certs.length})</h3>
              <ul className="list-disc pl-5 text-sm">
                {certs.map((id) => (
                  <li key={id}>{id}</li>
                ))}
              </ul>
              <h3 className="text-sm font-semibold">Services ({services.length})</h3>
              <ul className="list-disc pl-5 text-sm">
                {services.map((id) => (
                  <li key={id}>{id}</li>
                ))}
              </ul>
              {otherKinds.map((k) => (
                <div key={k}>
                  <h3 className="text-sm font-semibold">
                    {KIND_LABELS[k] ?? k} ({result.affected_by_kind[k].length})
                  </h3>
                  <ul className="list-disc pl-5 text-sm">
                    {result.affected_by_kind[k].map((id) => (
                      <li key={id}>{id}</li>
                    ))}
                  </ul>
                </div>
              ))}
            </section>
            {cov ? (
              <p className="text-xs text-muted-foreground">
                Edge coverage: {cov.certs_with_service_edge} of {cov.certs_total}{" "}
                certificates have a served-service edge ({cov.basis}). Impact is
                only as complete as these edges.
              </p>
            ) : null}
          </div>
        </Panel>
      ) : null}
    </div>
  );
}
