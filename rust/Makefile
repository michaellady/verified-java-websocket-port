# Rust workspace gates for the verified Java -> Rust WebSocket port.
# Targets mirror the PRD qualityGates commands exactly. Run from rust/:
#   make -C rust gates
# The root Makefile is intentionally untouched; wiring these targets into the
# root build is a follow-up owned by the pipeline stories.

TOOLCHAIN_BIN_DIR ?= $(HOME)/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin
RUSTGATE_CARGO = cd .. && go run ./cmd/rustgate cargo --root . --toolchain-bin-dir "$(TOOLCHAIN_BIN_DIR)" --validation-time "$$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ)" --

.PHONY: gates metadata-check fmt-check clippy test test-release

gates: metadata-check fmt-check clippy test test-release

metadata-check:
	$(RUSTGATE_CARGO) metadata --locked --offline --format-version 1 > /dev/null

fmt-check: metadata-check
	$(RUSTGATE_CARGO) fmt --all -- --check

clippy: metadata-check
	$(RUSTGATE_CARGO) clippy --workspace --all-targets --all-features --locked --offline -- -D warnings

test: metadata-check
	$(RUSTGATE_CARGO) test --workspace --all-targets --all-features --locked --offline

test-release: metadata-check
	$(RUSTGATE_CARGO) test --workspace --all-targets --all-features --release --locked --offline
