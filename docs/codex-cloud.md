# Codex cloud environment

The cloud worker uses a Linux amd64 universal image plus a repository-owned,
fail-closed bootstrap. The bootstrap downloads only exact public artifacts,
checks their byte counts and SHA-256 digests, and verifies every installed tool's
reported version before making the environment available to an agent.

## Environment settings

In Codex cloud environment settings, select this repository and configure:

- setup script: `GOTOOLCHAIN=auto go run ./cmd/cloudsetup setup --root .`
- maintenance script: `GOTOOLCHAIN=auto go run ./cmd/cloudsetup maintain --root .`
- setup internet access: enabled
- agent internet access: disabled unless a specific task requires and records it
- secrets: none

The setup phase writes an idempotent managed block to `~/.bashrc`; setup-process
environment exports do not otherwise persist into the agent phase. Codex may
cache this environment, so the maintenance command rechecks immutable downloads,
the Kani source identity, tracked-source cleanliness, and tool versions.

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
