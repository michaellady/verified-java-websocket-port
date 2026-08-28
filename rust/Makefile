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
ledger-gates:
	cd .. && go run ./cmd/deltaledgerctl --root . --check
