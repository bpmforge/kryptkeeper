# App Map — every screen, how you reach it, and what gates it

Derived from source (`ui/src/App.tsx`, `ui/src/lib/nav.ts`) on 2026-07-31, not
from memory. Regenerate the cross-check any time with the command at the bottom.

**This is the page graph, not a click-by-click manual.** It tells you every
destination and the exact path to it. It does not yet capture every button,
field and confirmation dialog inside each screen — see "What is missing" below.

## Before you look at this UI

`npm run dev` starts MSW unconditionally (`ui/src/main.tsx`, gated only on
`import.meta.env.DEV`) and serves `ui/src/mocks/fixtures.ts` — 247 certificates,
84 endpoints, a populated activity feed, none of which exist. It also accepts
any credentials at the login form.

Anything you review, screenshot or document there is a fixture. For real
behaviour, build the production bundle and serve it against the API:

```bash
npm --prefix ui run build     # DEV false, so MSW never starts
# then serve ui/dist with /api proxied to the backend
```

See the 2026-07-31 UI review for the full setup.

## Shape

- **34** top-level routes (plus 8 detail routes taking an `:id`)
- **31** of them reachable from the sidebar, in **4** groups
- **3** permission-gated
- **0** dead nav entries, **0** unreachable screens

## Navigation

Sidebar group → item → path.

### Operations

| Item | Path | Gate |
|---|---|---|
| Dashboard | `/` | — |
| Certificates | `/certificates` | — |
| Certificate Authorities | `/cas` | — |
| Keys | `/keys` | — |
| Code Signing | `/code-signing` | — |
| SPIFFE | `/spiffe` | — |
| Templates | `/templates` | — |
| Approvals | `/approvals` | — |
| Pending Actions | `/pending-actions` | — |

### Discovery

| Item | Path | Gate |
|---|---|---|
| Discovery | `/discovery` | — |
| Search | `/search` | — |

### Reports

| Item | Path | Gate |
|---|---|---|
| Crypto Posture | `/crypto-posture` | — |
| CA Health | `/reports/ca-health` | — |
| Expiry Timeline | `/reports/expiry-timeline` | — |
| Revocation Activity | `/reports/revocation-activity` | — |
| Issuance Velocity | `/reports/issuance-velocity` | — |
| Change Audit | `/reports/change-audit` | — |
| Compliance Evidence | `/reports/compliance-evidence` | — |
| Algorithm Sunset | `/reports/algorithm-sunset` | — |
| PQC Migration | `/reports/pqc-migration` | — |

### System

| Item | Path | Gate |
|---|---|---|
| Alerts | `/alerts` | — |
| Audit Log | `/audit` | `canReadOperationalSummaries` |
| History | `/history` | — |
| Users | `/users` | `canManageUsers` |
| Tenants | `/tenants` | — |
| Agents | `/agents` | — |
| Target Setup | `/targets/setup` | — |
| Renewal Policy | `/targets/renewal-policy` | — |
| Automation | `/automation` | — |
| Integrations | `/integrations` | `canReadOperationalSummaries` |
| Settings | `/settings` | — |

## Screens with no sidebar entry

Three, all correctly absent rather than orphaned:

| Path | Reached by |
|---|---|
| `/certificates/issue` | the issue action on **Certificates** — the issuance wizard |
| `/login` | pre-authentication |
| `/*` | not-found fallback |

## Detail routes

Reached by selecting a row, never from the sidebar:
`/alerts/deliveries/:id` · `/audit/:id` · `/cas/:id` ·
`/certificates/:fingerprint` · `/discovery/endpoints/:id` · `/history/:actionId`

## What is missing, and why it matters

This map is complete at the **screen** level and silent at the **element**
level. A real click-by-click manual needs, per screen, every button, field,
confirmation dialog and error state — and those cannot be extracted reliably
from source: many are icon-only, rendered from arrays, or supplied by the
component library, so a regex over the TSX finds some and misses more. A
partial element inventory presented as complete would be worse than none,
because it reads as coverage.

Capturing it properly means driving the running app and recording each state.
Until that happens this file is the honest artifact: the complete page graph,
verified against source.

## Regenerate the verification

```bash
node -e '
const fs=require("fs");
const app=fs.readFileSync("ui/src/App.tsx","utf8"), nav=fs.readFileSync("ui/src/lib/nav.ts","utf8");
const routes=[...app.matchAll(/path="([^"]+)"/g)].map(m=>m[1]);
const navTo=[...nav.matchAll(/to:\s*"([^"]+)"/g)].map(m=>m[1]);
const top=routes.filter(r=>!r.includes(":")&&r!=="*");
const navSet=new Set(navTo), routeSet=new Set(routes);
console.log("routes",top.length,"nav",navTo.length);
console.log("no nav:",top.filter(r=>!navSet.has(r)).join(" "));
console.log("dead nav:",navTo.filter(n=>!routeSet.has(n)).join(" ")||"(none)");
'
```

A new screen that never appears in the sidebar, or a sidebar item pointing at a
route that no longer exists, shows up as a non-empty line.
