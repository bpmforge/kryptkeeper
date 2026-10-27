# Roadmap process

[`ROADMAP.md`](ROADMAP.md) is the public list of what Kryptkeeper does not do yet.
It stays honest only if every deferral lands there when it is made.

## The rule

Any feature, test or fix that a thread decides not to do for the current release
must be added to `docs/ROADMAP.md` **in the same PR** that records the decision
(the board ticket, the `DECISIONS.md` entry, the live-results note or the scan report).

A PR that defers something without a roadmap row is not ready to merge.

## How to add a row

1. Pick the theme section that fits; add a section only if none does.
2. Write the item and its "why it matters" for a customer, in plain language. Describe
   the missing capability, not the internal finding.
3. Give one target: `1.1`, `Later`, `Needs an account` (a cheap or free trial, or a cloud or
   SaaS account), `Needs partner or hardware` (a vendor, customer or purchase), or
   `Not planned` (with the reason in the row). The two `Needs` targets mean built and tested
   against stand-ins, waiting on the real system.
4. Put the ticket or decision id in `Ref` so the next thread can see the item is
   already listed.
5. Update the "Last updated" date.

## Removing a row

Delete the row in the PR that ships the item or proves it on the real system.
