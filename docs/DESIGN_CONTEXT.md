# Design Context

## Deployment
- Runs locally / on-prem for now.
- No cloud target selected yet.
- Should work in constrained enterprise environments.

## Scale
- Initial users: a small PKI team.
- Data volume may grow significantly as larger companies onboard.
- Design should avoid UI patterns that break down with large inventories.

## Scope for v1
- Improve the UI and usability first.
- Make inventory, discovery, alerts, and CA management easier to use.
- Support faster triage and routine PKI/crypto operations.

## What is not yet defined
- External system integrations are not identified yet.
- Large-scale deployment architecture is not being designed yet.
- Advanced automation expansion is a later phase.

## Constraints
- Keep the current Go backend and React frontend.
- Prefer additive changes.
- Preserve auditability and access control.
- Keep local/on-prem operation simple.

## Design priorities
1. Inventory visibility
2. Drill-down from summary to detail
3. Action-oriented workflows
4. Search, filter, and bulk navigation patterns
5. Better operational feedback and error states

## UX direction already chosen
- Industrial/utilitarian
- Risk-first
- Task-oriented
- Dense but readable

## Recommended implementation posture
- Build on existing endpoints where possible.
- Add only the missing detail/action endpoints needed by the new UI.
- Keep the v1 scope centered on usability, not platform expansion.

## Notes for later phases
- When larger companies arrive, revisit deployment topology, caching, queueing, and observability.
- For now, optimize for clarity and low-friction operations.
