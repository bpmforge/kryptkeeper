// Container helpers for the targets E2E specs (W33-26). Everything shells out to
// `podman` (never docker), only ever touches resources named with the `kkw33-`
// prefix that THIS run created, and uses bounded waits only.
import { execFile, execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileP = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(here, "../../..");

/** Compose project the hub runs in (its default network and tls-trust volume derive from it). */
export function composeProject(): string {
  return process.env.E2E_COMPOSE_PROJECT ?? "kkw33-b";
}
const network = (): string => `${composeProject()}_default`;
const trustVolume = (): string => `${composeProject()}_tls-trust`;
/** The hub as the other containers on the compose network reach it. */
export const HUB_URL_IN_NETWORK = "https://kryptkeeper:8080";

export const randomId = (n = 6): string =>
  crypto.randomBytes(n).toString("hex").slice(0, n);

export function elapsedMs(since: number): number {
  return Date.now() - since;
}

export const sleep = (ms: number): Promise<void> =>
  new Promise((r) => setTimeout(r, ms));

async function podman(
  args: string[],
  env?: NodeJS.ProcessEnv,
): Promise<string> {
  const { stdout } = await execFileP("podman", args, {
    env: { ...process.env, ...env },
    maxBuffer: 32 * 1024 * 1024,
  });
  return stdout;
}

async function podmanArch(): Promise<"arm64" | "amd64"> {
  const arch = (await podman(["info", "--format", "{{.Host.Arch}}"])).trim();
  return arch === "arm64" || arch === "aarch64" ? "arm64" : "amd64";
}

/** Copies a fixture dir under tests/live into a throwaway build context (the originals stay untouched). */
function stageContext(src: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "kkw33-ctx-"));
  fs.cpSync(path.join(REPO_ROOT, src), dir, { recursive: true });
  return dir;
}

async function buildImage(tag: string, context: string): Promise<void> {
  // apt mirrors flake (exit 100); the fixtures install packages at build time, so retry once.
  let last = "";
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      await podman(["build", "-t", tag, context]);
      return;
    } catch (e) {
      const err = e as { stderr?: string; message: string };
      last = (err.stderr ?? err.message).slice(-1500);
      await sleep(2_000);
    }
  }
  throw new Error(`podman build ${tag} failed after 3 attempts: ${last}`);
}

async function removeContainer(name: string): Promise<void> {
  await podman(["rm", "-f", name]).catch(() => undefined);
}
async function removeImage(tag: string): Promise<void> {
  await podman(["rmi", "-f", tag]).catch(() => undefined);
}

// ---------------------------------------------------------------- agent

export interface AgentHandle {
  container: string;
  logs(): Promise<string>;
  stop(): Promise<void>;
}

export interface AgentFixture {
  /** Starts the agent with the enrollment token in its ENVIRONMENT only (never argv). */
  start(opts: {
    token: string;
    name: string;
    type: string;
    pollSeconds?: number;
  }): Promise<AgentHandle>;
  dispose(): Promise<void>;
}

/**
 * Builds the tests/live/agent fixture image (unmodified Containerfile) with a
 * linux agent binary for the podman machine's arch, built from this checkout.
 */
export async function buildAgentFixture(): Promise<AgentFixture> {
  const arch = await podmanArch();
  const ctx = stageContext("tests/live/agent");
  const tag = `localhost/kkw33-e2e-agent:${randomId()}`;
  const started: string[] = [];
  try {
    execFileSync(
      "go",
      [
        "build",
        "-o",
        path.join(ctx, "kryptkeeper-agent"),
        "./cmd/kryptkeeper-agent",
      ],
      {
        cwd: REPO_ROOT,
        env: { ...process.env, GOOS: "linux", GOARCH: arch, CGO_ENABLED: "0" },
        stdio: "pipe",
      },
    );
    await buildImage(tag, ctx);
  } finally {
    fs.rmSync(ctx, { recursive: true, force: true });
  }

  return {
    async start({ token, name, type, pollSeconds = 2 }) {
      const container = `kkw33-e2e-agent-${randomId()}`;
      started.push(container);
      // `-e NAME` with no value forwards the variable from this process's env,
      // so the token never appears in the podman argv (ps, shell history).
      await podman(
        [
          "run",
          "-d",
          "--name",
          container,
          "--network",
          network(),
          "-v",
          `${trustVolume()}:/etc/kryptkeeper/tls:ro`,
          "-e",
          `KRYPTKEEPER_HUB_URL=${HUB_URL_IN_NETWORK}`,
          "-e",
          "KRYPTKEEPER_HUB_CA_CERT_FILE=/etc/kryptkeeper/tls/ca.pem",
          "-e",
          `KRYPTKEEPER_AGENT_NAME=${name}`,
          "-e",
          `KRYPTKEEPER_AGENT_TYPE=${type}`,
          "-e",
          `KRYPTKEEPER_POLL_INTERVAL=${pollSeconds}`,
          "-e",
          "KRYPTKEEPER_ENROLL_TOKEN",
          tag,
        ],
        { KRYPTKEEPER_ENROLL_TOKEN: token },
      );
      return {
        container,
        logs: async () => {
          const { stdout, stderr } = await execFileP("podman", [
            "logs",
            container,
          ]);
          return stdout + stderr;
        },
        stop: () => removeContainer(container),
      };
    },
    async dispose() {
      for (const c of started) await removeContainer(c);
      await removeImage(tag);
    },
  };
}

/** Polls the agent log until `re` matches (250 ms cadence); returns the match time (epoch ms). */
export async function waitForAgentLog(
  agent: AgentHandle,
  re: RegExp,
  capMs = 30_000,
): Promise<number> {
  const deadline = Date.now() + capMs;
  let last = "";
  while (Date.now() < deadline) {
    last = await agent.logs().catch(() => "");
    if (re.test(last)) return Date.now();
    await sleep(250);
  }
  throw new Error(
    `agent log never matched ${re} within ${capMs} ms; tail:\n${last.slice(-1500)}`,
  );
}

// ---------------------------------------------------------------- sshd

export interface SshdFixture {
  /** Hostname on the compose network (the hub dials this, port 22). */
  host: string;
  user: string;
  /** PEM private key that sshd authorizes. Generated per run, never committed. */
  privateKey: string;
  /** A freshly generated key that sshd does NOT authorize. */
  wrongPrivateKey: string;
  /** authorized_keys-format ed25519 host public key (no comment). */
  hostPublicKey: string;
  /** SHA256:... fingerprints of every host key sshd holds (ssh-keygen -lf form). */
  hostFingerprints: string[];
  dispose(): Promise<void>;
}

function genKey(
  dir: string,
  name: string,
): { private: string; public: string } {
  const file = path.join(dir, name);
  execFileSync(
    "ssh-keygen",
    ["-q", "-t", "ed25519", "-N", "", "-C", "kkw33-e2e", "-f", file],
    { stdio: "pipe" },
  );
  return {
    private: fs.readFileSync(file, "utf8"),
    public: fs.readFileSync(`${file}.pub`, "utf8").trim(),
  };
}

function fingerprintOf(pubLine: string, dir: string): string {
  const f = path.join(dir, `fp-${randomId()}.pub`);
  fs.writeFileSync(f, `${pubLine}\n`);
  const out = execFileSync("ssh-keygen", ["-lf", f], { encoding: "utf8" });
  return out.split(/\s+/)[1] ?? "";
}

/** Throwaway sshd + nginx container from tests/live/ssh-install, joined to the compose network. */
export async function startSshd(): Promise<SshdFixture> {
  const keys = fs.mkdtempSync(path.join(os.tmpdir(), "kkw33-keys-"));
  const ctx = stageContext("tests/live/ssh-install");
  const tag = `localhost/kkw33-e2e-sshd:${randomId()}`;
  const container = `kkw33-e2e-sshd-${randomId()}`;
  const cleanup = async (): Promise<void> => {
    await removeContainer(container);
    await removeImage(tag);
    fs.rmSync(keys, { recursive: true, force: true });
    fs.rmSync(ctx, { recursive: true, force: true });
  };
  try {
    const good = genKey(keys, "good");
    const wrong = genKey(keys, "wrong");
    // The fixture Containerfile COPYs authorized_keys from its build context.
    fs.writeFileSync(path.join(ctx, "authorized_keys"), `${good.public}\n`);
    await buildImage(tag, ctx);
    await podman([
      "run",
      "-d",
      "--name",
      container,
      "--network",
      network(),
      "-e",
      "ROLE=nginx",
      tag,
    ]);

    const deadline = Date.now() + 30_000;
    for (;;) {
      const logs = await execFileP("podman", ["logs", container]).then(
        (r) => r.stdout + r.stderr,
        () => "",
      );
      if (/Server listening on/.test(logs)) break;
      if (Date.now() > deadline)
        throw new Error(`sshd never listened; log tail:\n${logs.slice(-800)}`);
      await sleep(250);
    }

    const pubs = (
      await podman([
        "exec",
        container,
        "sh",
        "-c",
        "cat /etc/ssh/ssh_host_*_key.pub",
      ])
    )
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);
    const ed = pubs.find((l) => l.startsWith("ssh-ed25519 "));
    if (!ed) throw new Error("sshd container has no ed25519 host key");
    return {
      host: container,
      user: "root",
      privateKey: good.private,
      wrongPrivateKey: wrong.private,
      hostPublicKey: ed.split(/\s+/).slice(0, 2).join(" "),
      hostFingerprints: pubs.map((l) => fingerprintOf(l, keys)),
      dispose: cleanup,
    };
  } catch (e) {
    await cleanup();
    throw e;
  }
}
