# Running this project in a Claude Code cloud environment

This document describes how to configure a cloud environment for the verified
Java to Rust WebSocket port, what that environment can do, and — the part worth
reading carefully — what it deliberately cannot.

## Configuring the environment

Cloud environments are configured in a dialog, not from a repository file. Open
[claude.ai/code](https://claude.ai/code), select the cloud icon above the message
box, then **Add cloud environment**. Fill in three fields:

**Name.** Anything; `vjwp` is fine.

**Network access.** Leave at **Trusted**. Every registry this project reaches is
already on the default allowlist: `crates.io` and `static.rust-lang.org` for the
Rust toolchain and crates, `rustup.rs` for rustup itself, `go.dev` and
`proxy.golang.org` for Go, `repo1.maven.org` and `maven.apache.org` for the
pinned Java-WebSocket 1.6.0 dependency, and `registry-1.docker.io`, `docker.io`
and `ghcr.io` for container images including the Autobahn test suite. There is
no need for **Custom** or **Full**.

**Setup script.** Paste the contents of [`cloud-setup.sh`](./cloud-setup.sh).
That file is kept in the repository so the script is reviewable and diffable
rather than living only in a web form; the dialog will not read it from here.

Leave **Environment variables** empty. See the AWS section below for why.

## What the environment already provides

Cloud sessions run Ubuntu 24.04 and ship with OpenJDK 21 plus Maven and Gradle,
Docker with compose, Go, git, gh, jq and ripgrep. OpenJDK 21 is sufficient for
`java-oracle`, which sets `maven.compiler.release 17` — a release target, not a
JDK requirement.

## What the setup script adds, and why it is mandatory

Rust **1.95.0**, installed through rustup.

The pre-installed Rust is not enough. `rust/rust-toolchain.toml` says the
channel must not float, and `cmd/rustgatectl`'s MSRV gate fails hard rather than
skipping when that exact toolchain is missing from rustup — its own message is
that "build-under-MSRV is a hard requirement and cannot execute, so the gate
FAILS rather than passing pending". A session without it cannot pass
`make -C rust gates`, and the failure would look like a project problem rather
than an environment one.

The script also installs Go 1.25 if, and only if, the pre-installed Go is older
than `go.mod` requires.

### What it deliberately does not install

`cargo-audit` and `cargo-deny` are absent from the local development machine
too, and the audit gate passes there regardless, reporting "zero non-path
dependencies (empty audit surface); audit tools absent, execution pending
availability". The workspace ships no external crates, so there is nothing for
either tool to audit.

Installing them in the cloud would therefore not strengthen the gate — it would
make the cloud environment's audit gate take a different code path from the
local one, so a cloud result and a local result would no longer be comparable.
The environment is built to match the local baseline rather than to exceed it.
If external dependencies are ever added, that decision should be revisited on
both planes at once.

## What works in a cloud session

- The full Rust gate suite: `make -C rust gates` — fmt, clippy with
  `-D warnings`, debug and release tests, and the eight AC1 gates.
- The Go suite: `go build ./...` and `go test ./...`.
- The Java oracle: Maven resolves the pinned Java-WebSocket 1.6.0 from Maven
  Central.
- Autobahn conformance runs: Docker is present and Docker Hub is allowlisted, so
  the pinned `crossbario/autobahn-testsuite` image can be pulled.

## What does not work, and why

### The protected governance store

This is the significant one. The owner-decision records that govern this project
live at `workspace/orchestrator/verified-java-websocket-port-claude/protected/`
inside HQ. HQ is local-only and is never pushed, so those records are not in this
repository and cannot be cloned.

That matters because of a deliberate design decision. The owner ruled that
governance records are mirrored into the repository **as digests only** — never
as content — because this repository is public and the records carry internal
deliberation, cost figures and infrastructure identifiers. The ruling's binding
implementation note is that the check must treat an unreachable store as a
**refusal, not a skip**, since skipping when the store is absent is
indistinguishable from a passing check and is precisely the hole the mirror
exists to close.

The consequence follows directly: once `claude/ledger-integrity` merges,
`ledger-gates` will **refuse** in any checkout that cannot reach the protected
store, and a cloud session is exactly such a checkout. This is the gate working
as designed, not a defect to route around. Do not set `VJWP_PROTECTED_STORE` to
a stub or copy the records into the repository to make it pass — that would
defeat the guard and publish the content the owner chose to withhold.

Run `ledger-gates` on the local plane. A cloud session can still run the Rust
and Go suites, which do not depend on the store.

### HQ orchestration state

Execution records, review receipts, drafts, the scoreboard, the behaviour-delta
ledger's owner decisions, and the worktrees all live in HQ rather than in this
repository. A cloud session can do repository work — write code, run gates, open
pull requests — but cannot update orchestrator state or write receipts to their
canonical locations. Treat cloud sessions as contributors to the repository, not
as participants in the orchestration layer.

### AWS native conformance runs

Do not put AWS credentials in the environment's variables field. The
documentation is explicit that environment variables are ordinary variables
"visible to anyone who uses the environment", and these grant the ability to
launch instances and incur cost. The native x86_64 conformance runs stay on the
local plane, where the credentials already live and where teardown is verified
directly.

### Kani

Docker is available, so the sandboxed verifier is not impossible, but the Kani
toolchain is a large install that will not fit inside the five-minute setup
budget without pushing the environment cache out of reach. Install it on demand
inside a session if a particular task needs it, rather than in the setup script.

## Setup script constraints, for whoever edits it next

Three rules govern that file and are easy to violate by accident:

1. **It must exit zero.** A non-zero exit prevents the session from starting at
   all, which is worse than a session that starts with a diagnosable problem.
   The script therefore prints warnings and exits zero unconditionally.
2. **It must finish within about five minutes**, or the environment cache cannot
   build and every new session pays the full cost again. The Rust and Go
   installs run concurrently for this reason.
3. **It runs as root, but the session may not.** Toolchains go into
   `/usr/local/rustup` and `/usr/local/cargo` rather than root's home, are made
   world-readable, and are put on `PATH` for every user through
   `/etc/profile.d/vjwp-toolchains.sh`.

One syntax trap is worth recording because it is silent. In
`rustup toolchain install`, `--component` takes a **comma-separated** list;
`rustup component add` takes space-separated values. Writing
`--component rustfmt clippy` in the first form does not add two components — it
is parsed as a second *toolchain name*, and rustup tries to install a toolchain
called `clippy`. The script uses the comma form, with a comment saying why.

## Verifying the environment actually works

The setup script prints every tool's real version at the end rather than
assuming the installs succeeded, and states explicitly whether the MSRV
toolchain is present. After creating the environment, start a session and
confirm from that output that `rustc 1.95.0` is installed via rustup. Then run:

```
make -C rust gates
```

and read the result. If `ac1-gates` reports `gates_passed=8/8` and the msrv gate
does not complain about a missing toolchain, the environment is correct.
