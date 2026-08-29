# Codex cloud environment

The cloud worker uses a Linux amd64 universal image plus a repository-owned,
fail-closed bootstrap. Artifact downloads have exact byte-count and SHA-256
bindings. Kani is checked out at an exact commit and tree, built from its locked
Rust dependency graph, and accepted only while its tracked source remains clean.
The bootstrap verifies every installed tool's reported version before making the
environment available to an agent.

## Environment settings

In Codex cloud environment settings, select this repository's Ubuntu 24.04
universal image on Linux amd64 and configure:

- setup script: `GOTOOLCHAIN=auto go run ./cmd/cloudsetup setup --root .`
- maintenance script: `GOTOOLCHAIN=auto go run ./cmd/cloudsetup maintain --root .`
- setup internet access: enabled
- agent internet access: disabled unless a specific task requires and records it
- secrets: none

The setup phase writes an idempotent managed block to `~/.bashrc`; setup-process
environment exports do not otherwise persist into the agent phase. Codex may
cache this environment, so the maintenance command rechecks immutable downloads,
materialized directory types, the Kani source identity and cleanliness, and all
tool versions.

The exact materialized locations can be inspected without changing state:

```sh
go run ./cmd/cloudsetup paths --root .
```

## Trust and claim boundary

This cloud run is a second host and operating system, which is valuable for
portability and replay. It is still an owner-directed Codex run using repository
instructions authored in the same project. It must not be labeled an independent
human review, hidden/sealed validation, Java equivalence proof, production
authorization, or proof of concurrent scheduling.

The Linux worker uses the probed Eclipse Temurin 17.0.19+10 archive. That is the
same compiler version used by the semantic-oracle contract, but it is not the
Darwin Homebrew JDK artifact retained by the original promoted toolchain. A
byte-identical regenerated semantic report demonstrates cross-distribution
replay; it does not replace or extend the original toolchain provenance claim.

The cloud environment deliberately avoids `rust/Makefile`: that wrapper checks a
Darwin-specific promoted toolchain and is expected to reject Linux. The direct
Linux commands and nonclaims are recorded in the root `AGENTS.md`.

For the project's formal lane, `cloudsetup` installs the exact Kani source used
locally and the published Ubuntu 24.04 CBMC 6.11.0 package in a private cache. It
does not use `sudo`, `apt`, `dpkg`, or Kani's upstream dependency installer. The
upstream cvc5 and Kissat installers are intentionally not invoked: neither tool
is called by this repository's `cmd/kanidriver` execution graph. Kani's nightly
Rust toolchain is fixed by the bound source tree; rustup verifies the official
distribution manifest, while Cargo verifies locked registry package checksums.
Formal executions still retain their own tool-binary digests in evidence.
