import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api, type CredentialSource } from "../lib/api";
import { Button, Input, Select, Textarea } from "./ui";

// W38-07 (D-324): the "fetch from a secret manager" half of the credential
// form. The hub stores a reference and the non-secret fixed fields; the secret
// is fetched from the source at each use. Nothing typed here is a secret.

export type ExternalField = { key: string; label: string; secret?: boolean };

export type ExternalCredentialValue = {
  sourceId: string;
  reference: Record<string, string>;
  fixed: Record<string, string>;
  valid: boolean;
};

// "key=value" per line, for plugin sources whose reference keys are the
// plugin's own (CyberArk safe/object, Secret Server secret_id).
function parsePairs(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const i = line.indexOf("=");
    if (i > 0 && line.slice(i + 1).trim() !== "")
      out[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  return out;
}

export function ExternalCredentialFields({
  credentialType,
  fields,
  onChange,
}: {
  credentialType: string;
  fields: ExternalField[];
  onChange: (v: ExternalCredentialValue) => void;
}) {
  const sourcesQ = useQuery({
    queryKey: ["credential-sources"],
    queryFn: api.credentialSources,
  });
  const sources: CredentialSource[] = sourcesQ.data?.data?.items ?? [];
  const [sourceId, setSourceId] = useState("");
  const [path, setPath] = useState("");
  const [version, setVersion] = useState("");
  const [pairs, setPairs] = useState("");
  const [fixedValues, setFixedValues] = useState<Record<string, string>>({});

  const source = sources.find((s) => s.id === sourceId);
  // The parent builds `fields` fresh on every render, so effects key on its
  // content, not its identity (an identity dependency here loops forever).
  const fieldsKey = fields.map((f) => `${f.key}${f.secret ? "!" : ""}`).join(",");
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const fixedFields = useMemo(() => fields.filter((f) => !f.secret), [fieldsKey]);
  const fetchedFields = fields.filter((f) => f.secret);

  const reference = useMemo<Record<string, string>>(() => {
    if (source?.kind === "vault_kv2") {
      return {
        ...(path.trim() ? { path: path.trim() } : {}),
        ...(version.trim() ? { version: version.trim() } : {}),
      };
    }
    return parsePairs(pairs);
  }, [source?.kind, path, version, pairs]);
  const fixed = useMemo(() => {
    const out: Record<string, string> = {};
    for (const f of fixedFields) {
      const v = (fixedValues[f.key] ?? "").trim();
      if (v) out[f.key] = v;
    }
    return out;
  }, [fixedValues, fixedFields]);

  const valid =
    !!source &&
    Object.keys(reference).length > 0 &&
    (source.kind !== "vault_kv2" || !!reference.path);
  useEffect(() => {
    onChange({ sourceId, reference, fixed, valid });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sourceId, reference, fixed, valid]);

  const testM = useMutation({
    mutationFn: () =>
      api.testCredentialSource(sourceId, {
        credential_type: credentialType,
        reference,
        static: fixed,
      }),
  });
  const result = testM.data?.data;

  return (
    <div className="space-y-3" data-testid="external-credential-fields">
      <label className="block space-y-1 text-sm text-foreground">
        <span>Secret manager</span>
        <Select
          value={sourceId}
          onChange={(e) => {
            setSourceId(e.target.value);
            testM.reset();
          }}
        >
          <option value="">Select a credential source…</option>
          {sources.map((s) => (
            <option key={s.id} value={s.id}>
              {s.name} ·{" "}
              {s.kind === "vault_kv2"
                ? "Vault / OpenBao KV v2"
                : `plugin ${s.config.plugin_id ?? ""}`}
            </option>
          ))}
        </Select>
      </label>
      {!sourcesQ.isLoading && sources.length === 0 && (
        <p className="text-xs text-muted-foreground">
          No credential sources yet. Create one with the API (POST
          /api/v1/credential-sources); see docs/ops/CREDENTIAL_SOURCES.md.
        </p>
      )}

      {source?.kind === "vault_kv2" && (
        <div className="grid gap-3 sm:grid-cols-[1fr_8rem]">
          <label className="block space-y-1 text-sm text-foreground">
            <span>Secret path</span>
            <Input
              value={path}
              onChange={(e) => setPath(e.target.value)}
              placeholder="ssh/web1"
              spellCheck={false}
            />
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Version (optional)</span>
            <Input
              value={version}
              onChange={(e) => setVersion(e.target.value)}
              placeholder="latest"
              inputMode="numeric"
            />
          </label>
        </div>
      )}
      {source?.kind === "plugin" && (
        <label className="block space-y-1 text-sm text-foreground">
          <span>Reference (one key=value per line)</span>
          <Textarea
            rows={3}
            value={pairs}
            onChange={(e) => setPairs(e.target.value)}
            placeholder={
              "safe=Infra\nobject=web1-root\nmap=Content:private_key_pem,UserName:user"
            }
            spellCheck={false}
          />
        </label>
      )}

      {fixedFields.length > 0 && (
        <div className="space-y-2">
          <p className="text-xs text-muted-foreground">
            Fixed values the manager does not hold. Leave blank any the secret
            already has.
          </p>
          {fixedFields.map((f) => (
            <label
              key={f.key}
              className="block space-y-1 text-sm text-foreground"
            >
              <span>{f.label}</span>
              <Input
                value={fixedValues[f.key] ?? ""}
                onChange={(e) =>
                  setFixedValues((m) => ({ ...m, [f.key]: e.target.value }))
                }
              />
            </label>
          ))}
        </div>
      )}
      {fetchedFields.length > 0 && (
        <p className="text-xs text-muted-foreground">
          Fetched from the manager at each use, never stored here:{" "}
          {fetchedFields.map((f) => f.label).join(", ")}.
        </p>
      )}

      <Button
        tone="secondary"
        disabled={!valid || testM.isPending}
        onClick={() => testM.mutate()}
      >
        {testM.isPending ? "Fetching…" : "Test reference"}
      </Button>
      {testM.isError && (
        <p className="text-sm text-state-over" role="alert">
          {testM.error instanceof Error ? testM.error.message : "Test failed"}
        </p>
      )}
      {result && (
        <p
          className={
            result.ok ? "text-sm text-foreground" : "text-sm text-state-over"
          }
          role={result.ok ? "status" : "alert"}
          data-testid="external-credential-test"
        >
          {result.ok
            ? `Fetched. The secret provides: ${(result.fields ?? []).join(", ")}.`
            : (result.error ?? "The secret could not be fetched.")}
        </p>
      )}
    </div>
  );
}
