# Rust workspace gates for the verified Java -> Rust WebSocket port.
# Targets mirror the PRD qualityGates commands exactly. Run from rust/:
#   make -C rust gates
# The root Makefile is intentionally untouched; wiring these targets into the
# root build is a follow-up owned by the pipeline stories.

.PHONY: gates metadata-check fmt-check clippy test test-release

gates: metadata-check fmt-check clippy test test-release

metadata-check:
	cargo metadata --locked --offline --no-deps --format-version 1 > /dev/null

fmt-check: metadata-check
	cargo fmt --all -- --check

clippy: metadata-check
	cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings

test: metadata-check
	cargo test --workspace --all-targets --all-features --locked --offline

test-release: metadata-check
	cargo test --workspace --all-targets --all-features --release --locked --offline
