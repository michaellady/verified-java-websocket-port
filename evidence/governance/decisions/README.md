# Owner-decision records

The 62 JSON files beside this README are the owner-decision records that
authorise the work on this plane: scope rulings, sandbox attempt
authorisations, acceptance-criteria amendments, and the corrections that
supersede earlier statements.

They are a **published mirror**. The canonical store remains outside this
repository, at
`workspace/orchestrator/verified-java-websocket-port-claude/protected/` in HQ,
and it is append-only: a correction is a NEW record, never an edit to an
existing one.

## Why they are here

The earlier ruling mirrored these records into the repository **as digests
only**, on the stated grounds that the repository is public and the records
carry internal deliberation, cost figures and infrastructure identifiers.

That assessment was measured afterwards and found to be overstated. Across all
62 records there are no credentials of any kind — no keys, no ARNs, no bucket
names. The genuinely identifying content was one AWS account id and one EC2
instance id. Several earlier flags dissolved on inspection: an "email address"
that was the `git@github.com` SSH remote, an instance id that was an attempt
number matching the same pattern, and an IP address that was loopback.

The owner therefore superseded the digests-only ruling and directed that the
records be published with those identifiers redacted. Publishing them makes the
store reachable from a cloud session or a fresh clone, which the digests-only
arrangement could not do.

## What was redacted, and what was not

| token | disposition |
| --- | --- |
| the AWS dev account id | replaced with `REDACTED-AWS-ACCOUNT-ID` (1 occurrence, in `us008-owner-pinning-tier1.json`) |
| an EC2 instance id | replaced with `REDACTED-EC2-INSTANCE-ID` (1 occurrence, in `us019-native-provenance-and-ac3-owner-decision-2026-08-28.json`) — the instance is long terminated; redacted for hygiene rather than necessity |
| `ami-02b3d83d84b07786d` | **not** redacted. It is a public Amazon Linux 2023 image id; publishing it discloses nothing that is not already public, and it is load-bearing provenance for the native run. |
| local `/Users/...` paths | **not** redacted. They reveal a username that already matches the public GitHub account, so redaction would buy nothing while corrupting paths that receipts cite. |

The redaction was performed **during the copy**, not afterwards. Unredacted
content was never written into a git worktree, because doing so would create a
window in which a careless `git add` publishes it permanently.

## The four records that must not drift

Four of these records have their sha256 asserted inside the behaviour-delta
ledger's hashed rationales. They contain none of the redacted tokens and were
verified byte-identical to the canonical store after copying:

| record | sha256 prefix |
| --- | --- |
| `governance-mirroring-and-record-schema-owner-decision-2026-08-28.json` | `e6837006a722b71f` |
| `ledger-frozen-prefix-owner-decision-2026-08-28.json` | `bb3cd0da7f4aed01` |
| `us010-016-ac-amendment-owner-decision-2026-08-27.json` | `26849b5ea7400650` |
| `us012-us016-owner-decisions-2026-08-28-formal.json` | `d7a54e2c5aac48cc` |

If a future redaction ever touches one of these, its digest changes and the
ledger's assertion breaks. Check this table before editing anything here.

## Using this store

Point the governance gate at this directory:

```bash
export VJWP_PROTECTED_STORE=<repo-root>/evidence/governance/decisions
```

`ledger-gates` then recomputes each mirrored digest against these files. The
gate treats an unreachable store as a **refusal, not a skip** — that behaviour
is deliberate and must not be weakened, because a skip when the store is absent
is indistinguishable from a passing check.

## What is still not here

The review receipts under `workspace/reports/dev-team/reviews/` in HQ, the
orchestrator execution records, the drafts, and the race scoreboard. Those are
coordination state rather than authorisation, and nothing in the repository's
gates depends on them.
