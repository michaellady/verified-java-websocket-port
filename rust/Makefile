# Rust workspace gates for the verified Java -> Rust WebSocket port.
# Targets mirror the PRD qualityGates commands exactly. Run from rust/:
#   make -C rust gates
# The root Makefile is intentionally untouched; wiring these targets into the
# root build is a follow-up owned by the pipeline stories.

.PHONY: gates fmt-check clippy fixture-guard test test-release ac1-gates ledger-gates

gates: fmt-check clippy fixture-guard test test-release ac1-gates ledger-gates

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
# -max-waivers is the escape hatch's ceiling and is currently 0. A fixture that
# genuinely needs a count guard carries an in-source
# `// FIXTURE-COUNT-GUARD-ALLOWED: <justification>` AND a raise of this number
# in the same change, so the pile is visible in review instead of growing
# quietly. Raising it is a decision, not a formality.
fixture-guard:
	cd .. && go test ./cmd/fixtureguardctl/
	cd .. && go run ./cmd/fixtureguardctl -root . -max-waivers 0

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
# DIGESTS ONLY). Deleting or editing a governance record fails this target.
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
