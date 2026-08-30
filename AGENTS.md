# Cloud verification instructions

This repository is an evidence-backed Java-to-Rust port. Preserve the distinction
between a passing check and the claim that check is allowed to support.

## Environment

The Codex cloud environment must run this setup command from the repository root:

```sh
GOTOOLCHAIN=auto go run ./cmd/cloudsetup setup --root .
```

Use the same command with `maintain` after a cached environment is resumed. It
materializes digest-pinned public inputs, JDK 17.0.19, Maven 3.9.11, Rust
1.95.0, source-pinned Kani 0.67.0, its exact nightly Rust compiler, and the
digest-pinned CBMC 6.11.0 Ubuntu package. It also restores the public project
history required by historical evidence without moving the checked-out commit
or changing working-tree bytes. It requires Ubuntu 24.04 on Linux amd64. No
secret is required. The repository bootstrap must not call Kani's upstream
system-dependency installer. The bootstrap also materializes and verifies the
exact evidence-bound Java oracle adapter needed by the Go replay gates.

## Canonical cloud checks

Run these from the repository root. Do not use `rust/Makefile` in the cloud: its
`rustgate` authority is intentionally restricted to the retained Darwin host.

```sh
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
cargo +1.95.0 fmt --manifest-path rust/Cargo.toml --all -- --check
cargo +1.95.0 clippy --manifest-path rust/Cargo.toml --workspace --all-targets --all-features --locked --offline -- -D warnings
cargo +1.95.0 test --manifest-path rust/Cargo.toml --workspace --all-targets --all-features --locked --offline
cargo +1.95.0 test --manifest-path rust/Cargo.toml --workspace --all-targets --all-features --release --locked --offline
go run ./cmd/portplanctl verify --root .
make -C java-oracle test JAVA_WEBSOCKET_JAR=../.quarantine/Java-WebSocket-1.6.0.jar RUNTIME_SUPPORT_CP=../.quarantine/slf4j-api-2.0.13.jar
```

Run Kani only through the checked-in `cmd/kanidriver` evidence workflow, using
the `VJWP_KANI_ROOT` and `VJWP_CBMC_ROOT` paths installed by `cloudsetup`. Kani
sequentializes atomics and does not prove overlapping thread schedules. A
passing owner FIFO harness is bounded serialization evidence, not a concurrency
proof, Java equivalence proof, independent review, or release authorization.

Do not rerun Autobahn: the authorized attempt budget has been consumed and its
original receipts must remain intact. Do not edit during a review-only task. Fix
only blocking correctness or security findings, then move to QA/reality checks.
