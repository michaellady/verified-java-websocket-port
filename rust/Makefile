# Rust workspace gates for the verified Java -> Rust WebSocket port.
# Targets mirror the PRD qualityGates commands exactly. Run from rust/:
#   make -C rust gates
# The root Makefile is intentionally untouched; wiring these targets into the
# root build is a follow-up owned by the pipeline stories.

.PHONY: gates fmt-check clippy test test-release ac1-gates ledger-gates

gates: fmt-check clippy test test-release ac1-gates ledger-gates

fmt-check:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

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
