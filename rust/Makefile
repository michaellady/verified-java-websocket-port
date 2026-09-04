# Rust workspace gates for the verified Java -> Rust WebSocket port.
# Targets mirror the PRD qualityGates commands exactly. Run from rust/:
#   make -C rust gates
# The root Makefile is intentionally untouched; wiring these targets into the
# root build is a follow-up owned by the pipeline stories.

.PHONY: gates fmt-check clippy fixture-guard record-guard pin-guard plan-guard go-suite test test-release ac1-gates ledger-gates oracle-hierarchy-gates

gates: fmt-check clippy fixture-guard record-guard pin-guard plan-guard go-suite test test-release ac1-gates ledger-gates oracle-hierarchy-gates

fmt-check:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

# Count-shaped liveness guards in Rust test fixtures. This program has filed
# the SAME defect three times — F002 (a backpressure fixture sized to a host's
# socket buffer), F004 (`refusals_before_the_drop < 4096`, 2 red runs in 5 with
# ws-core byte-identical), F005 (`polls < POLL_BUDGET`, a red `test-release`
# with `left: 179 right: 200` under load and no defect anywhere) — and each
# time the remedy was a paragraph in drafts/self-review/findings/ that bound
# nothing. F005's own bin note says so: "a portable rule that lives only in a
# findings file does not bind anything". This target is the binding.
#
# It runs BOTH halves on purpose, for the reason ledger-gates records below:
#   * `go test` executes the fine-grained polarity assertions (the waiver
#     ceiling, the empty-scan refusal, the drifted-manifest refusal). Five of
#     the fourteen recorded deletion attacks on this detector are caught ONLY
#     here, so leaving the tests out of a release path would leave those five
#     parts deletable in silence.
#   * `go run` applies the rule to the live tree and re-runs the historical
#     polarity control in production code, printing what fired on the pre-fix
#     text of F004 and F005 and refusing to PASS if the scan matched no files
#     or no loops.
#
# -max-waivers is the escape hatch's ceiling for the in-fixture shapes A and B
# and is currently 0; -max-budget-waivers is shape C's own ceiling and is also
# 0. They are SEPARATE numbers on purpose: shape C reaches across an
# indirection into a production loop bound, and admitting a backlog there must
# never be able to raise the ceiling on the shapes F004 and F005 actually cost
# red gates for. A fixture that genuinely needs a count guard carries an
# in-source `// FIXTURE-COUNT-GUARD-ALLOWED: <justification>` AND a raise of
# the matching number in the same change, so the pile is visible in review
# instead of growing quietly. Raising either is a decision, not a formality.
fixture-guard:
	cd .. && go test ./cmd/fixtureguardctl/
	cd .. && go run ./cmd/fixtureguardctl -root . -max-waivers 0 -max-budget-waivers 0

# A self-review record read for its CONTENT, never counted for its presence.
# F009: three wave-4 branches were judged complete by `git log --oneline` plus a
# COUNT of files matching `drafts/self-review`, and reported to the owner as
# "each ends with a self-review record". Two of the three did.
# claude/div05-close-overtakes-echo carried a nine-line stub — "STATUS: IN
# PROGRESS … Nothing verified yet" — behind seven commits and 983 insertions of
# finished-looking code. It was caught only because someone opened the file.
#
# WHAT THIS TARGET DOES AND, MORE IMPORTANTLY, DOES NOT DO. It does NOT refuse
# unfinished records in the tree, and it carries no ceiling on them. That is
# deliberate and it is the one place this target departs from fixture-guard's
# shape above. This repository's own discipline tells an agent to commit and
# push a stub within its first few tool calls so a container restart cannot lose
# the branch; a ceiling here would gate against a practice the loop mandates,
# and F009's edge is explicit that writing "IN PROGRESS" while genuinely in
# progress is CORRECT. The failure is LANDING on such a record. So the refusal
# lives at the landing decision, in GOAL-LOOP.md step 6:
#
#     go run ./cmd/recordguardctl precondition <record>...   exit 1 if unfinished
#
# and what this target does is keep that refusal ALIVE and honest. It runs BOTH
# halves for the same reason fixture-guard does:
#   * `go test` executes the assertions no tree scan can reach — that an ABSENT
#     record is a refusal and not a pass (F009's defect stated directly), that a
#     mixed batch of two real records and one stub fails as a batch, that naming
#     no record at all is a usage refusal, and that the gate does NOT fail on an
#     honestly-unfinished record while the landing check still refuses the same
#     file. One of the twelve recorded deletion attacks (A11, an absent record
#     passing) is caught ONLY here, and a second (A12) was until the fixture
#     that lets the gate see it was added.
#   * `go run ... gate` replays the discriminator in production code over
#     records extracted verbatim from git — the div05 stub at blob 359940cd
#     among them — printing what fired and the sentence it was read from, and
#     refusing to PASS if it read no records at all.
# The work plan, as data rather than prose.
#
# What this replaces read a markdown board and picked "one bounded unit" per
# firing. The one-unit rule was ignored every firing, priorities were re-derived
# from prose each time, and blocked-versus-ready lived only in whoever was
# reading. A prose plan also ROTS: `normalization-collision-audit.md` stated 26
# distinct observations while the artifact it cited measured 29, for hours,
# because nothing read the prose.
#
# So the plan is checked. Dangling references and cycles fail; readiness is
# recomputed rather than read; a node cannot stay blocked once every owner action
# it names is ruled (the state an outside ruling silently invalidates); and --
# the load-bearing rule -- a `done` node must cite evidence this gate RE-DERIVES,
# not merely name some. `command` evidence is recorded and never counted, so it
# cannot masquerade as a verified claim. On its first run this gate caught F011's
# `.quarantine` symlink tracked again, re-added by an agent's `git add -A`.
plan-guard:
	cd .. && go test -count=1 ./cmd/taskgraphctl/
	cd .. && go run ./cmd/taskgraphctl -root .

# Digest pins that name a file whose bytes have moved.
#
# This census was INFORMATIONAL until now: `dangling` exited 1 with eleven rows
# while `make -C rust gates` exited 0, both true at once, which meant F014's real
# drifted pin failed nothing and a pin drifting tomorrow would be equally
# invisible. Wiring it in as-is was not possible either: all eleven are blocked on
# something outside the loop's reach, and halting on those would not fix them.
#
# So each of the eleven is DECLARED, pinned to its own declared digest and named
# with the owner action that would let the entry be deleted. A NEW drift fails on
# the run it appears; a pin that gets FIXED orphans its allowance and fails as
# STALE_ALLOWANCE; and editing an allowed pin loses the acknowledgement rather
# than inheriting it, so an allowance covers a finding and not an address.
pin-guard:
	cd .. && go test -count=1 ./cmd/pinconsumerctl/
	cd .. && go run ./cmd/pinconsumerctl dangling -root .

# The Go suite, as a gate, with its exclusions DECLARED.
#
# This chain exited 0 all of 2026-09-03 while internal/deltaledger was failing
# three subtests -- two of them the governance gate ACCEPTING a document it
# exists to refuse -- because the chain simply did not run the Go packages, and
# "gates green" was read as "the tree is good". Repeatedly, by the loop itself.
#
# gosuitectl runs everything `go list ./...` reports EXCEPT a named list with a
# reason per entry, and it FAILS on a stale exclusion, so the list cannot outlive
# the problem it describes and a package added tomorrow is covered without anyone
# remembering. It REFUSES (exit 2) when `.quarantine/` is not staged, naming the
# `ln -s` that fixes it -- the same shape as ledger-gates refusing without
# VJWP_PROTECTED_STORE, and for the same reason: an unstaged tree cannot tell a
# blocked package from a broken one.
go-suite:
	cd .. && go test -count=1 ./cmd/gosuitectl/
	cd .. && go run ./cmd/gosuitectl -root . -timeout 40m

record-guard:
	cd .. && go test ./cmd/recordguardctl/
	cd .. && go run ./cmd/recordguardctl gate -root .

test:
	cargo test --workspace --all-targets --all-features

test-release:
	cargo test --workspace --release

# US-009 AC1 workspace gates: forbid(unsafe_code) enforcement scan,
# dependency-unsafe inventory, MSRV, license, audit, reproducible lockfile,
# and the good/bad scaffold canary polarity run. Implemented as the
# repo-incumbent Go tool cmd/rustgatectl (unit polarity tests:
# go test ./cmd/rustgatectl/). The runner reads and prints every external
# command's exit code verbatim (gate=... step=... exit=N lines) and exits
# nonzero if any gate fails, which fails this target and `gates` with it.
ac1-gates:
	cd .. && go run ./cmd/rustgatectl -root .

# Behavior-delta ledger integrity. Independent review (session 01a0495e,
# BLOCKING 3) found that every census and observation-integrity rule this
# repository had lived only in `_test.go` files which no release or readiness
# path executed: this target had no `go test` step, there is no root Makefile,
# no workflow runs Go tests, and `deltaledgerctl --check` verified only that the
# ledger equalled its own regeneration. The rules now live in
# internal/deltaledger as production code and `--check` runs them, so the gate
# and the test suite exercise one implementation. It exits nonzero on any
# integrity failure, which fails this target and `gates` with it.
#
# ROUND 2 moved two more rules in, for the same reason: the JSON-schema
# validation of the evidence documents and the observation envelope and
# uniqueness checks were still test-only, so an unknown census field or a
# drifted observation `$schema` passed this target at exit 0.
#
# THE GOVERNANCE BINDING IS REQUIRED, NOT OPTIONAL. `--check` now verifies the
# committed digest mirror at evidence/governance/owner-decision-digests.json
# against the workspace orchestrator's protected store, under the owner ruling
# governance-mirroring-and-record-schema-owner-decision-2026-08-28.json (MIRROR
# DIGESTS ONLY). Deleting or editing a MIRRORED governance record fails this
# target. That is 7 of the 63 records in the store, and the other 56 were
# measured on 2026-09-04: deleting one is exit 0, with this target still
# reporting "7 governance record digest(s) recomputed ... and matched" --
# true, and true of 7. The sentence here used to read "a governance record"
# unqualified, which claimed the other 56 as well. Widening the mirror is an
# owner decision (OA-governance-mirror-coverage), because the mirror is
# DERIVED from the ledger's own digest citations, so widening it moves a
# declared count and re-opens a disclosure question the owner already ruled.
# An UNREACHABLE store is also a failure rather than a skip — skipping when
# VJWP_PROTECTED_STORE was unset is exactly how deleting a load-bearing owner
# decision used to leave this branch green. The store is discovered above the
# checkout when the variable is unset; set VJWP_PROTECTED_STORE to point at it
# explicitly from a checkout that does not sit under the workspace.
#
# ROUND 3 moved in the last of the identity checks that lived only in test
# binaries. `--check` now re-derives corpora/public/scenarios.jsonl and
# corpora/handshake/cases.jsonl from the committed seed, and
# evidence/us005-handshake-live-mapping.json from the source-derived table it is
# rendered from. Those three files are INPUTS to the divergence measurement, so
# an edit to any of them moves what the gate is able to demand; each was
# previously bound only by internal/corpora's tests, which no release path runs.
ledger-gates:
	cd .. && go run ./cmd/deltaledgerctl --root . --check

# US-020 AC2 oracle hierarchy. AC2 says RFC 6455 is rank one, in-scope Autobahn
# rank two, independent neutral expectations rank three, Java observation rank
# four and Rust observation rank five, and that agreement between Java and Rust
# cannot override a higher oracle. A criteria audit found that sentence had no
# mechanism anywhere in the tree: one prose string in
# internal/deltaledger/definitions_gap_closure.go, no type, no field, no check.
# The consequence was concrete -- the 74/74 public-corpus differential and the
# 247-case Autobahn per-case comparison this repository cites as parity are both
# rank-four-against-rank-five comparisons, exactly the comparison AC2 says
# cannot settle a question on its own.
#
# internal/oraclerank is the mechanism and this target executes it.
# `oraclerankctl --check` recomputes the adjudication register from the
# committed evidence (the register is never an input to its own recomputation),
# refuses any difference, and then checks the adjudication rules themselves:
# every Java/Rust agreement a higher oracle overrides is enrolled, no enrolled
# entry is unexhibited, the guarded parity reading refuses on every overridden
# agreement, no rank is declared and then silent, and the pure
# rank-four-against-rank-five family exhibits no override at all. It exits
# nonzero on any failure, which fails this target and `gates` with it.
oracle-hierarchy-gates:
	cd .. && go run ./cmd/oraclerankctl --root . --check
