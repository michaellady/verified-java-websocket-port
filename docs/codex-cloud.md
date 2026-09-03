# Codex cloud environment

The cloud worker uses a Linux amd64 universal image plus a repository-owned,
fail-closed bootstrap. Artifact downloads have exact byte-count and SHA-256
bindings. Kani is checked out at an exact commit and tree, built from its locked
Rust dependency graph, and accepted only while its tracked source remains clean.
The bootstrap restores the public project history needed by retained evidence,
then verifies every installed tool's reported version before making the
environment available to an agent. The history fetch must leave both `HEAD` and
the working-tree status unchanged.

## Environment settings

In Codex cloud environment settings, select this repository's Ubuntu 24.04
universal image on Linux amd64 and configure:

- setup script: `GOTOOLCHAIN=auto go run ./cmd/cloudsetup setup --root "$PWD" --home "$HOME"`
- maintenance script: `GOTOOLCHAIN=auto go run ./cmd/cloudsetup maintain --root "$PWD" --home "$HOME"`
- setup internet access: enabled
- agent internet access: disabled unless a specific task requires and records it
- secrets: none

The setup phase prepends an idempotent managed block to `~/.bashrc`, ahead of
Ubuntu's early return for non-interactive shells; setup-process environment
exports do not otherwise persist into the agent phase. A cached legacy block at
the end of the file is moved without changing unrelated shell content. Codex may
cache the container home while checking out a fresh repository workspace for the
agent. Tool downloads therefore use the default cache under `$HOME`, not a
repository-local `--cache-home`; otherwise a successful setup can be followed by
a network-blocked agent trying to download the same tools again. The maintenance
command rechecks project history,
immutable downloads, materialized directory types, the Kani source identity and
cleanliness, and all tool versions. Setup also rebuilds the Java oracle adapter
with the repository's canonical Go JAR writer and rejects any digest other than
the adapter retained by the differential manifest. That writer fixes entry
order, manifest bytes, timestamps, modes, and the uncompressed ZIP method, so
JDK vendor and host ZIP implementations cannot change the adapter identity.

The exact materialized locations can be inspected without changing state:

```sh
go run ./cmd/cloudsetup paths --root "$PWD" --home "$HOME"
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
