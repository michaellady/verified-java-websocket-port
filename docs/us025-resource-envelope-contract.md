# US-025 resource-envelope decision contract

## Decision and claim boundary

US-025 is split into two truths that must never be collapsed:

1. **decision mechanics** may complete under the owner's relaxation; and
2. **measurement acceptance** remains `INCONCLUSIVE_BLOCKED` until authorized
   raw evidence exists for both bound native hosts and a provenance-distinct
   recomputation accepts it.

The maximum result available in the current phase is
`PASS_OWNER_RELAXED_MECHANICS`. It means that the repository can enumerate the
entire frozen decision surface, represent absent raw evidence honestly, reject
hostile inputs, and refuse a performance claim. It does not mean that Rust is
smaller, faster, non-regressed, measured, or independently confirmed.

Every US-025 result must carry:

```text
assurance: OWNER_ATTESTED_NOT_INDEPENDENT
independent_review_claimed: false
mechanics_status: PASS_OWNER_RELAXED_MECHANICS | BLOCKED
measurement_acceptance: INCONCLUSIVE_BLOCKED
performance_claimed: false
primary_host: NOT_BOUND
confirmation_host: NOT_BOUND
samples_authorized: false
```

`performance_claimed` may become true only in a separately authorized future
measurement phase after both host states are `BOUND`, both raw ledgers are
complete, and independent recomputation succeeds. The mechanics pass itself
must not change that ceiling.

## Shipped result

US-025 completed the owner-relaxed decision mechanics at repository head
`84935acb5665ed50bd5eb718e918ed19adfcc646` and tree
`838fd4f551312447af3be1958916a1c5c2b5c885`. The result is exactly
`PASS_OWNER_RELAXED_MECHANICS` with measurement acceptance
`INCONCLUSIVE_BLOCKED`. Both hosts remain `NOT_BOUND`, both raw paths remain
`ABSENT`, samples remain unauthorized and uncollected, and
`performance_claimed` remains false.

The committed mechanics enumerate the complete two-host by six-workload by
ten-endpoint surface before inspecting raw evidence. The resulting 12 workload
decisions and 120 endpoint decisions are all `INCONCLUSIVE`, all validations
are `BLOCKED`, and every reason is `RAW_ABSENT`. Two real invocations of
`benchplanctl envelope --root .` emitted byte-identical 27,707-byte JSON and
returned the dedicated inconclusive exit code 4.

The exact sample-free receipt digests are:

```text
benchmarks/analysis/primary.json
  sha256:25a128b62a72193ea117ac2836ab2e479d28b0db7d09ba72f19b51019ce4f9c0
benchmarks/analysis/confirmation.json
  sha256:143ed3644bf41d876cf17f964fec8750f6a93e49221b7dedd2bba9af36654056
benchmarks/analysis/recompute-receipt.json
  sha256:aee0149d907ad7146c4b6c420f8e73a38b79119129b95307869b7fa86f44e817
evidence/performance.json
  sha256:645b18936d8939fdbf21c9877f29f7627c7a40aae7f3ab05bfd6129a0c10cd22
```

One full comments-only review found four blocking evidence-boundary defects.
The one permitted targeted closure closed `B-US025-002` through
`B-US025-004`; `B-US025-001` then received one final bounded remediation and
was validated by QA and fresh reality without a second review or second
closure. Fresh-checkout validation ran 101 focused top-level tests. The review
fix selection contained seven named tests with 42 closure-field subcases, and
the guarded raw-append command stopped with exit 4 before reading a payload or
creating `benchmarks/raw/`.

Three important review notes remain intentionally unimplemented:

```text
I-US025-001 raw-entry schema is broader than runtime acceptance
I-US025-002 canonical JSON encoding is not enforced
I-US025-003 committed mechanics receipts are not machine-linked to reconstruction
```

The retained nit is that the top-level CLI comment documents exit codes 0-3
but not public exit 4. These items do not expand the bounded completion claim.

All shipped claim-bearing result artifacts remain
`OWNER_ATTESTED_NOT_INDEPENDENT` with `independent_review_claimed:false`. The
nine measurement blockers and five nonclaims in the retained section below
remain authoritative.

## Facts resolved at architecture time

The implementation must extend the incumbent US-008 machinery rather than
create a second statistics framework:

- `internal/benchplan/seed.go` freezes exactly six ordered workload IDs and the
  five-warmup/30-measured structure.
- `internal/benchplan/decide.go:28-46` already defines typed endpoint outcomes;
  `internal/benchplan/decide.go:86-105` freezes the ten decision metrics and
  thresholds.
- `internal/benchplan/decide.go:108-130` binds the current ten-item identity
  closure, and `internal/benchplan/decide.go:173-338` rejects invalid role,
  binding, order, count, validity, noise, power, and summary inputs.
- `internal/benchplan/bundle.go:33-169` already verifies an exact 6 x 10
  endpoint bundle, including missing, duplicate, extra, and raw-digest cases.
- `internal/benchplan/stats.go:41-90` performs the frozen paired log-ratio
  calculation and requires exactly 30 finite, strictly positive pairs.
- `internal/benchplan/drift.go:60-107` enforces background CPU, thermal, power,
  identity, invalid-sample, and reference-drift observations.
- `internal/benchplan/power.go:8-97` freezes alpha 0.025, minimum power 0.8,
  maximum log-ratio SD 0.10, and the named alternatives.
- `cmd/benchplanctl/main.go:33-53` is the incumbent CLI seam. Its existing
  `verify` and `order` commands remain unchanged.

The current host truth is exact and blocking:

- `benchmarks/environments/primary-macos.json:6-7` says `binding_status:
  UNBOUND` and `OWNER_ATTESTED_NOT_INDEPENDENT`.
- `benchmarks/environments/confirmation.json:6-7` says the same. The pinned
  c7i.xlarge class, region, AMI, and pipeline-tool facts are not an allocated,
  isolated, immediately pre-sample host binding.
- `cmd/benchplanctl/main_test.go:11-55` pins the real-tree result to
  `HOST_BINDING_PENDING`, including 26 currently unbound fields.
- Both requested raw paths are absent. No zero, sentinel, fixture, retained
  pipeline output, or observed host fact is a sample.

The six workloads remain, in order:

```text
wl-01-handshake-close
wl-02-small-text-echo
wl-03-fragmented-64kib-binary-echo
wl-04-control-mix
wl-05-cap-rejection
wl-06-concurrent-pressure
```

The ten threshold endpoints remain exactly those in
`internal/benchplan/decide.go:86-105`. File-descriptor and Java-GC data are
required supporting observations, not new threshold endpoints. They cannot
turn a failing endpoint into a pass or be averaged across workloads.

## Selected architecture

Add one outer campaign decision layer to `internal/benchplan`. It owns evidence
presence, the two-host/six-workload matrix, the stronger US-025 identity
closure, raw-ledger integrity, and campaign aggregation. It delegates every
statistical endpoint to the existing `DecideEvidenceBundle` and
`DecideEndpoint` functions.

Conceptually:

```go
type MeasurementDecision string // THRESHOLD_MET, THRESHOLD_NOT_MET, INCONCLUSIVE
type ValidationState string      // VALID, BLOCKED

type HostWorkloadDecision struct {
    EnvironmentRole   string
    WorkloadID        string
    Decision          MeasurementDecision
    Validation        ValidationState
    EndpointDecisions map[string]Decision // exactly ten, stable order on output
    ReasonCodes       []string
}

type ResourceEnvelopeDecision struct {
    MechanicsStatus       string
    MeasurementAcceptance string
    RawState              map[string]string
    Workloads             []HostWorkloadDecision // exactly 12
    IndependentRecompute  string
    Assurance             string
    Nonclaims             []string
}
```

The public result uses two axes deliberately. Malformed evidence is a
`Validation: BLOCKED` fact, while the performance `Decision` remains
`INCONCLUSIVE`. This retains the detailed `OutcomeBlocked` behavior inside the
existing endpoint validator without allowing an invalid input to become a
performance decision. Campaign acceptance is `INCONCLUSIVE_BLOCKED` whenever
any workload is inconclusive, any endpoint fails validation, either host is not
bound, or independent recomputation is absent.

### Complete enumeration before input inspection

The campaign function first constructs the canonical Cartesian product:

```text
[primary, confirmation] x [six WorkloadIDs] x [ten MetricNames]
```

It pre-populates all 120 endpoints and all 12 workload/host results as
`INCONCLUSIVE` with `RAW_ABSENT`. Only then does it inspect evidence. Therefore
an empty repository still has a deterministic typed answer for every required
workload/host, and a malformed or partial file can never make decisions
disappear from the report.

Aggregation is per workload and host. A workload is `THRESHOLD_MET` only if all
ten endpoints are `THRESHOLD_MET` and all supporting observations validate. It
is `THRESHOLD_NOT_MET` if complete valid evidence contains any threshold
failure. It is otherwise `INCONCLUSIVE`. There is no host-wide or campaign-wide
average that can mask a workload failure.

### Safest absent-raw representation

The safe representation is **path absence**:

```text
benchmarks/raw/primary.jsonl       does not exist
benchmarks/raw/confirmation.jsonl  does not exist
```

The decision report records `raw_state: ABSENT`; it contains no sample values.
Do not create empty JSONL files, zero-valued rows, `NOT_MEASURED` rows, empty
MEASURED bundles, or synthetic fixtures under `benchmarks/raw/`. An empty file
is `PRESENT_INVALID`, not `ABSENT`, because it could otherwise hide a failed or
interrupted writer. The existing evidence-bundle schema requires 60 actual
MEASURED endpoints and is therefore not an absence container.

### Append-only raw ledger if measurement is later authorized

Each host path becomes a hash-chained JSONL ledger only after both hosts and the
entire identity closure are bound. Its first entry is a `BINDING_CLOSURE`
record that predates every sample. Later entries are either an existing
US-008 raw endpoint payload or one workload-support payload. Every line carries
the environment role, monotonically contiguous sequence, previous-entry
digest, exact payload digest, and binding-closure digest.

The writer belongs in `benchplanctl raw-append`, not in a shell script. It:

1. acquires an adjacent lock with `O_CREATE|O_EXCL`; a present or stale lock
   fails closed rather than being stolen;
2. opens a new ledger with `O_CREATE|O_EXCL|O_APPEND`, or an existing ledger
   with `O_APPEND` only;
3. parses and verifies the entire current chain before one append;
4. encodes exactly one newline-terminated record, performs the append, and
   calls `fsync`;
5. never truncates, rewrites, deletes, repairs, or replaces a partial record;
   and
6. removes its lock only after a clean result. A crash or panic may strand the
   lock or a partial tail, both of which block subsequent use and require an
   explicit evidence-preserving recovery decision.

This is dependency-free Go transport logic. Direct writes to either ledger are
unsupported and rejected by the chain verifier. The analyzer receipt binds the
ledger byte length, whole-file SHA-256, record count, and terminal entry digest;
later recomputation rejects a shorter file, changed prefix, broken chain,
duplicate sequence, reordered entry, replacement, or extra post-completion
entry. Exactly one closure plus 60 endpoint records plus six support records is
accepted per host. Partial ledgers remain evidence, but decide nothing.

The shipped transport closes path and self-attestation races with held bytes,
not pathname re-resolution. `benchplanctl raw-append` first opens the real
repository and `benchmarks/raw` boundaries through `os.Root`, rejects symlinked
or substituted directories, and derives the expected closure from repository
facts before reading the caller's payload. Environment documents, referenced
receipts, source/adapter trees, and lockfiles are opened as regular files,
bounded, copied into a private verification snapshot, kept open across
verification, and re-read through the same descriptors before the closure is
accepted. Both exactly verified environment documents must be fully `BOUND`;
raw bytes cannot nominate their own expected identity.

The payload is likewise opened through a held directory/file descriptor and
must retain the same file identity, size, and bytes before and after its bounded
read. The append path acquires an adjacent exclusive lock under the held raw
root, verifies the entire existing ledger through its held descriptor, and
uses `O_APPEND` without truncation. When creating one host ledger while its
sibling already exists, it first verifies that sibling against the same
repository-derived closure. The writer synchronizes new directory entries and
the appended file; a partial write or failed sync preserves the lock and
evidence instead of repairing or retrying it.

### Strong US-025 identity closure

The first ledger record must contain nonzero SHA-256 digests for:

```text
plan
primary environment and exact primary host
confirmation environment and exact confirmation host
Java source, executable, and dependency lock
Rust source, executable, and dependency lock
thin TCP adapter
measurement-tool manifest
reference analyzer
each of the six workload definitions
each workload's derived 35-pair order
```

The closure also states `sbx_inside_measurement_boundary: false`. Host digests
bind the immediately pre-sample thermal, power, isolation, cache, process, and
runtime snapshots, not merely a machine class. Tool identity is a manifest of
the actual collectors and versions rather than one unstructured label.

Do not change the meaning of `vjwp-benchmark-raw-sample/1.0.0` or weaken its
ten existing bindings. The new ledger-entry schema binds the stronger closure
around the exact old payload bytes. The outer verifier checks both layers and
requires the payload's existing plan/environment/source/executable/adapter/
tool/analyzer digests to agree with the new closure.

### Supporting FD and Java-GC observations

One support record per workload/host retains the same 35 derived pair-order
positions: exactly five excluded warmups and 30 measured pairs. Each position
records positive Java and Rust file-descriptor counts at the preregistered
observation point and the complete Java GC event list for that run. A valid
empty GC-event list means the pinned collector observed no event; numeric zero
is not used as a missing-data sentinel. Every event carries a finite,
non-negative timestamp and finite, strictly positive duration, with the exact
collector-output digest retained in the closure. Missing, extra, duplicate, or
reordered support positions make that workload `INCONCLUSIVE` and validation
`BLOCKED`.

## Fail-closed algorithm

For each invocation, `benchplanctl envelope --root DIR` must:

1. verify the US-008 documents with the existing `Verify` path;
2. create the complete 12-workload/120-endpoint inconclusive matrix;
3. classify each raw path as `ABSENT`, `PRESENT_PARTIAL`,
   `PRESENT_COMPLETE`, or `PRESENT_INVALID`;
4. reject any sample-bearing ledger while either environment document is
   `UNBOUND` or the closure is incomplete;
5. verify ledger sequence, hash chain, exact role, canonical record order,
   payload digests, exact closure equality, and the exact 60+6 record set;
6. derive an in-memory existing `EvidenceBundle` and call
   `DecideEvidenceBundle` for every complete host;
7. validate all support records, map endpoint `BLOCKED` to workload
   `INCONCLUSIVE` plus retained validation blockers, and aggregate without
   masking; and
8. emit deterministic JSON even when raw is absent or invalid.

The CLI uses a dedicated exit code for `INCONCLUSIVE_BLOCKED`; exit zero is
reserved for complete accepted measurement evidence. Mechanics acceptance is
proven by green tests and the report's separate `mechanics_status`, never by
coercing absent evidence into CLI success.

## Hostile acceptance tests

All fixtures live under `internal/benchplan/testdata/` and are explicitly
`SYNTHETIC_FIXTURE_NOT_A_MEASUREMENT`. Tests use temporary directories and
must never create repository raw files.

Required cases are:

1. both raw paths absent: exactly 12 workload decisions and 120 endpoint
   decisions, all `INCONCLUSIVE/RAW_ABSENT`;
2. one host absent, empty, partial, or complete while the other is absent;
3. missing, extra, duplicate, or reordered ledger entry and endpoint;
4. truncated final line, broken previous digest, changed historical prefix,
   duplicate sequence, wrong role, and extra entry after completion;
5. zero, negative, `NaN`, and positive/negative infinity supplied through Go
   values, plus non-JSON nonfinite tokens rejected by decoding;
6. every old and new identity field missing, zero, malformed, or changed on
   either the raw or bound side;
7. wrong workload digest, pair-order digest, analyzer, source, executable,
   dependency lock, adapter, host, or measurement-tool digest;
8. 4/5/6 warmups, 29/30/31 measured pairs, reordered pair order, and optional
   stopping represented by a short ledger;
9. altered declared summary and raw/summary disagreement;
10. noise above the frozen SD limit, power below 0.8, reference drift,
    background CPU, thermal, power-state, identity, and invalid-sample
    violations;
11. missing/duplicate/reordered FD and GC support records, invalid FD counts,
    invalid GC event values, and an explicitly observed empty GC event list;
12. one endpoint regression and one workload regression proving neither can be
    hidden by other endpoint, workload, or host wins;
13. two concurrent append attempts proving exactly one lock owner and no
    interleaved line; and
14. injected writer error/panic state proving a stranded lock or partial tail
    blocks rather than repairs or truncates evidence.

Existing tests in `internal/benchplan/decide_test.go` and
`internal/benchplan/bundle_test.go` remain. New tests exercise the outer layer;
they do not rewrite old `BLOCKED` endpoint semantics merely to make campaign
wording say `INCONCLUSIVE`.

## Primitive Test

| Capability | Atomicity | Bitter Lesson | ZFC | Placement |
|---|---:|---:|---:|---|
| Enumerate and validate the fixed decision matrix | pass | pass | pass | Go, `internal/benchplan` |
| Verify schemas, digests, identities, counts, order, statistics, and drift | pass | pass | pass | incumbent Go analyzer |
| Serialize one append under exclusive ownership | pass | pass | pass | Go, `benchplanctl raw-append` |
| Decide whether missing evidence proves performance | fail | fail | fail | fixed claim policy: it never does |
| Authorize hosts, samples, retries, tuning, or acceptance expansion | fail | fail | fail | owner/prompt layer |
| Judge review findings | fail | fail | fail | bounded review phase |

No shell state machine, new statistics dependency, database, service, signing
system, or second benchmark framework is warranted.

## Implementation file plan

Smallest incumbent-framework extension:

```text
internal/benchplan/resource_envelope.go
internal/benchplan/resource_envelope_test.go
internal/benchplan/raw_ledger.go
internal/benchplan/raw_ledger_test.go
internal/benchplan/testdata/us025-*.json
cmd/benchplanctl/main.go
cmd/benchplanctl/main_test.go
schemas/benchmark-raw-ledger-entry-1.0.0.schema.json
schemas/benchmark-resource-envelope-decision-1.0.0.schema.json
benchmarks/analysis/primary.json
benchmarks/analysis/confirmation.json
benchmarks/analysis/recompute-receipt.json
evidence/performance.json
```

The four JSON result files may exist in mechanics-only form and must contain no
sample values. `benchmarks/raw/primary.jsonl` and
`benchmarks/raw/confirmation.jsonl` remain absent until separately authorized
measurement. No AWS, host, sbx, Docker, Autobahn, wstest, secret, or benchmark
operation belongs in mechanics implementation.

## Review, QA, and reality validation

Run exactly one complete comments-only review of the US-025 mechanics diff.
Fix only blocking correctness or security findings, then allow the same
reviewer one targeted closure over those fixes. List important findings and
nits without another full pass. Record provider, model, reasoning effort,
invocation, commits, and diff identity. This remains owner-attested and is not
independent human or provenance-distinct recomputation.

Local QA is mechanics-only:

```sh
go test ./internal/benchplan ./cmd/benchplanctl -count=1
go test ./... -count=1
go test -race ./internal/benchplan ./cmd/benchplanctl -count=1
go vet ./...
go build ./...
```

Reality validation uses a disposable clean checkout, confirms both raw paths
are absent, runs the real `benchplanctl envelope` command, observes its exact
`INCONCLUSIVE_BLOCKED` exit/result, and re-derives byte-identical mechanics
reports. It does not run a benchmark or provision a host. Synthetic fixture
passes validate the decision engine only and never populate evidence rows.

## Owner-relaxed done criteria

US-025 mechanics may be marked complete only when:

- the exact US-008 protocol, six workloads, pair order, statistics, power, and
  ten thresholds remain unchanged;
- absent raw paths deterministically produce all 12 typed workload/host and
  all 120 endpoint decisions as `INCONCLUSIVE`;
- both current hosts remain truthfully `NOT_BOUND`, samples remain
  unauthorized, and the campaign stays `INCONCLUSIVE_BLOCKED`;
- the stronger closure binds analyzer, sources, executables, locks, adapter,
  workloads, pair orders, both exact hosts, and tools;
- partial/missing/duplicate/reordered/nonpositive/nonfinite/identity/summary/
  noise/power/drift/support-observation cases fail closed;
- the only future raw writer is append-only and hostile concurrency/crash
  tests pass;
- one bounded review has no open blocking finding, local QA passes, and clean
  reality replay reproduces the mechanics result; and
- every original unavailable claim below remains explicit.

## Retained blockers and nonclaims

These original acceptance claims remain `INCONCLUSIVE_BLOCKED`:

```text
PRIMARY_NATIVE_HOST_NOT_BOUND
CONFIRMATION_LINUX_HOST_NOT_BOUND
SAMPLES_NOT_AUTHORIZED_OR_COLLECTED
DUAL_HOST_30_PAIR_EVIDENCE_NOT_EXECUTED
RESOURCE_THRESHOLDS_NOT_DECIDED
FD_AND_JAVA_GC_OBSERVATIONS_NOT_COLLECTED
INDEPENDENT_ANALYZER_REBUILD_NOT_EXECUTED
PROVENANCE_DISTINCT_RECOMPUTATION_NOT_EXECUTED
PERFORMANCE_TUNING_AND_AFFECTED_GATE_RERUNS_NOT_EXECUTED
```

The exact retained nonclaims are:

```text
no 20 percent memory win
no CPU, startup, latency, allocation, or throughput non-regression
no sufficient measured power or clean measured environment
no dual-host confirmation or independent recomputation
no publication, signing, production readiness, or cutover readiness
```

The owner-only assurance ceiling separately excludes any independent-review
claim.

## Provenance and attribution

Architecture worker runtime:

```text
provider: OpenAI
model: gpt-5.6-sol
reasoning_effort: xhigh
invocation: /root/us017_concurrency_research
start_head: 603ef0fdd5bb3f114d95b09e7282ee2a74c8e60a
branch: codex/race-catchup
```

No new Claude US-025 design or code was inspected or borrowed. This design
does reuse the incumbent US-008 implementation already present in the branch;
the canonical PRD attributes that foundation through Claude merge `66f33d4`
and Codex catch-up completion `39415fce46ffe538b5d30b2ddaf110c7011adb4f`.
That existing attribution remains intact and creates no new Codex first-finish
claim for US-008.

## Post-ship boundary

The fail-closed matrix and append-only evidence transport are implemented and
validated. No implementation handoff remains for US-025. Future measurement
work requires separate owner authorization and must begin by binding both
exact native hosts, tools, analyzers, sources, executables, locks, adapter,
workloads, and pair orders before creating either raw ledger.

Until that authorization and complete binding exist:

- do not create either raw path or manufacture a sample;
- preserve the endpoint validator's detailed `BLOCKED` results and translate
  them only at the outer claim layer;
- keep path absence as the sole `ABSENT` representation;
- keep mechanics status separate from measurement acceptance in every schema,
  CLI result, receipt, and project note; and
- do not infer measurement acceptance, independent recomputation, performance,
  publication, production, signing, or cutover from the mechanics pass.
