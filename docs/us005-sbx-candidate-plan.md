# US-005 sbx candidate execution plan (stub, mutants, sealed-network probe, rerun)

Machine-readable source of truth: `evidence/us005-sbx-candidate-plan.json`
(ordered steps, exact commands, flags). This page is the prose walkthrough.
Assurance: OWNER_ATTESTED_NOT_INDEPENDENT; no independent review is claimed.
This plan performs no sbx runs and records no live evidence itself — the
parent (owner) session executes it.

## What this closes

Four live gates in `evidence/corpus-calibration.json` remain
`BLOCKED_PENDING_LIVE_EXECUTION`:

1. `empty_rust_target_fails` — an empty/stub Rust target fails the corpus.
2. `planted_java_rust_mutants_killed` — planted mutants are killed with
   nonzero inventories.
3. `sealed_network_denial` — sealed-tier execution observes default-deny
   networking live.
4. `execution_rerun_reconciliation` — two candidate executions reconcile
   byte-identically (the java-oracle half already reconciled on 2026-08-26).

## The artifacts (built and locally proven in this change)

| Artifact | Where | Public-tier proof (read from real `corporactl evaluate`) |
|---|---|---|
| Inert Rust stub `us005-candidate-stub` | `rust/candidate-stub` | 74 executed / **0 passed / 74 failed**, exit 1 |
| Rust mutant `us005-rm-eager-reject-1002` | same crate, own bin | 0 passed / 74 failed, exit 1 |
| Rust mutant `us005-rm-digest-unbind` | same crate, own bin | 0 passed / 74 failed, exit 1 |
| Java mutant `us005-jm-close-code-1000` | `mutants/java/...` overlay + `cmd/us005-mutantctl` | 55 passed / **19 failed** (`close_code 1000, expected 1002`), exit 1 |
| Java mutant `us005-jm-utf8-accept` | `mutants/java/...` overlay | 72 passed / **2 failed** (`outcome ok, expected error`), exit 1 |
| Network probe `us005-netprobe` | `cmd/us005-netprobe` | host self-test: detects the OPEN network (exit 1) — must flip to denied/exit 0 in sbx |
| Pristine oracle separation baseline | unmodified `java-oracle` | 74/74 passed, exit 0; transcript byte-identical to the recorded live public transcript |

Full command log, digests, and verbatim reports:
`evidence/us005-candidate-public-proof.json`. Mutant deviations and kill
signatures: `mutants/manifest.json`. The pristine `java-oracle` tree is never
modified; mutants are staged copies assembled fail-closed by
`cmd/us005-mutantctl`.

## Custodian safety (verified from source, not assumed)

- Public-tier `oracle-requests`/`evaluate` spend **nothing**:
  `cmd/corporactl/main.go:217-219` (`heldOutTier` = hidden|sealed only),
  spends gated at `main.go:268-282` and `main.go:326-334`.
- Held-out `evaluate` spends one query keyed by
  `sha256("evaluate|"+tier+"|"+transcript)` — **a byte-different transcript is
  a fresh digest with count 1** (`internal/corpora/custodian.go:241`), so
  first-time candidate evaluations carry no probing risk. Failures also cost
  one diagnostic (`main.go:361-376`); diagnostics never feed the probing
  counter (`custodian.go:274-296`).
- `SpendCustodian` is flock-atomic and persists denials
  (`internal/corpora/spend.go:12-37`).

**Latch hazard — the reason this plan is careful.** The ledger already holds
four distinct digests at **2 of the 3-repeat threshold** (seq 1–8): the
`oracle-requests` digests for hidden and sealed, and the `evaluate` digests of
the recorded oracle transcripts for hidden and sealed (the byte-identical
rerun was the second occurrence). Therefore, permanently latching actions —
**forbidden**:

- any `oracle-requests --tier hidden|sealed` (re-emission = same digest,
  third occurrence). **Reuse**
  `protected/us005-corpora/live/<tier>/requests.jsonl`.
- any held-out `evaluate` of bytes identical to the recorded
  `live/<tier>/transcript.jsonl`.
- a third held-out `evaluate` of any transcript already evaluated twice.

The rerun-reconciliation step is the only step whose naive form walks into
this: reconcile by **sha256 equality of transcripts**, not by re-evaluating
identical bytes. Worst-case spend for the whole plan is ≤20 of 192 queries
and ≤10 of 50 diagnostics — budget is not the constraint; digest repetition
is.

## Execution outline (details in the JSON)

1. **Owner authorization** for a fresh candidate attempt (US-007 pattern).
   Note: `executions/US-007.json` freezes *US-007's own* generic sbx reruns;
   a US-005 candidate attempt is a distinct workload but still needs its own
   owner authorization — owner decision, not inherited from this plan.
2. **Cross-compile** for the sbx platform (linux/arm64, probed live):
   Go probe via `GOOS=linux GOARCH=arm64 CGO_ENABLED=0`; Rust candidates via
   `rustup target add aarch64-unknown-linux-musl` +
   `RUSTFLAGS='-C linker=rust-lld -C link-self-contained=yes' cargo build
   --release --target aarch64-unknown-linux-musl` (static ELF, no glibc
   dependency). Java mutant jars are platform-independent bytecode.
3. **Create the sandbox** with the accepted profile shape
   (`sbx create --clone --cpus 2 --memory 2g --deny-network '**' --template
   <pinned shell template digest> ...`, CLI pinned at v0.39.0). Candidates
   run unprivileged — no `--privileged`, no root.
4. **Deliver** binaries, the two pinned runtime jars, and the three recorded
   `requests.jsonl` files. Requests are candidate *inputs*; expectations,
   secrets, ledger, and canary inventory never enter the sandbox.
5. **Probe before wire**: `--identify` smoke, stdin piping smoke, and
   `command -v java`. If the template has no JVM, materialize a pinned
   linux/aarch64 JDK on the host (record URL + sha256 at fetch time) and copy
   it in — or record the java half BLOCKED. Never run mutants outside the
   sandbox and claim the gate.
6. **Run** all five candidates on all three tiers; run `us005-netprobe`
   inside the sandbox during the sealed window (expect `network_denied:true`,
   exit 0) plus the host-side `sbx policy check network` corroboration.
7. **Evaluate outside** the sandbox: public first (custodian-free), then
   hidden/sealed after the mandatory pre-check that no candidate transcript
   collides with the recorded oracle transcripts. Read every report and exit
   code; expected verdicts are pinned in `mutants/manifest.json`.
8. **Rerun** everything once (fresh sandbox preferred), reconcile by
   transcript digest equality, record, canary-sweep anything public-bound,
   destroy the sandboxes.

## Open decisions for the owner

- Mint the per-attempt authorization (step 1).
- JVM materialization if the template lacks `java` (step 5).
- Whether the recorded gate schema requires evaluate-backed rerun proof; if
  so, accept that each candidate transcript digest ends at 2 of 3 and freeze
  those bytes thereafter.
