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

### The governance store, and why you no longer need HQ for it

This used to be the blocker. It no longer is.

The owner-decision records that govern this project are now published in this
repository at `evidence/governance/decisions/` — 63 records plus a README.
Point the gate at them:

```bash
export VJWP_PROTECTED_STORE=<repo-root>/evidence/governance/decisions
```

`ledger-gates` then recomputes each mirrored digest against those files, and a
cloud session runs the full gate target like any other checkout.

An earlier ruling mirrored the records **as digests only**, on the stated
grounds that they carried internal deliberation, cost figures and
infrastructure identifiers. That assessment was measured afterwards and found
to be overstated: across all 62 records there were no credentials of any kind,
and the genuinely identifying content was one AWS account id and one EC2
instance id, both now redacted. Two independent scanners were run over the
published content. `gitleaks` reported no leaks across 588 KB. HQ's own secret
patterns produced a single false positive, on a findings identifier about a
masking round trip whose middle happens to match the OpenAI/Stripe key rule.
The owner then superseded the digests-only ruling.

**What has NOT changed, and must not:** an unreachable store is still a
REFUSAL, not a skip. Do not weaken that to make a checkout pass, and do not
point `VJWP_PROTECTED_STORE` at a stub. A gate that skips when a variable is
unset is indistinguishable from a passing gate, and that is the exact hole the
mirror exists to close.

The canonical store remains HQ and remains append-only. What is in the
repository is a MIRROR: corrections land in HQ as new records and are
re-published, never edited in place here. Four records have their digests
asserted inside the behaviour-delta ledger and must stay byte-identical; they
are listed in that directory's README.

## What does not work, and why

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
3. **It must install where the session's rustup looks.** Both the script and
   the session run as root, and the session shell carries
   `RUSTUP_HOME=/root/.rustup` in the environment the harness hands it, which
   overrides anything `/etc/profile.d` exports. So the script installs into
   rustup's default home and never sets `RUSTUP_HOME` or `CARGO_HOME`. An
   earlier revision installed into `/usr/local/rustup`; the toolchain landed
   there correctly and the session never saw it. The MSRV gate still passed in
   that session, but only because cargo's first run under
   `rust-toolchain.toml` made rustup install 1.95.0 on demand, which needs
   network at session time and hides the setup failure.

One syntax trap is worth recording because it is silent. In
`rustup toolchain install`, `--component` takes a **comma-separated** list;
`rustup component add` takes space-separated values. Writing
`--component rustfmt clippy` in the first form does not add two components — it
is parsed as a second *toolchain name*, and rustup tries to install a toolchain
called `clippy`. The script uses the comma form, with a comment saying why.

## Verifying the environment actually works

The setup script prints every tool's real version at the end rather than
assuming the installs succeeded, and states explicitly whether the MSRV
toolchain is present. That output is visible where the environment is built,
not from inside a session, so verify from the session as well, and do it before
the first cargo command: cargo's first run under `rust-toolchain.toml` asks
rustup to install a missing 1.95.0 on demand, which masks a setup script that
did not land.

```
rustup toolchain list
```

must already show `1.95.0-x86_64-unknown-linux-gnu`. Then run:

```
export VJWP_PROTECTED_STORE=$PWD/evidence/governance/decisions
make -C rust gates
```

and read the result. If `ac1-gates` reports `gates_passed=8/8` and the msrv gate
does not complain about a missing toolchain, the environment is correct.

The debug and release test steps run before `ac1-gates`, so a failing test
stops the chain before that line ever prints. Until 2026-09-02 the loopback
suite's stalled-writer test assumed macOS-sized socket buffers and failed on
Linux hosts that autotune the send buffer past its fixed 3 MiB flood, reporting
`SocketError("ConnectionReset")` after 60 seconds. It now feeds the
never-reading peer until the kernel refuses, with the core's per-connection
frame and action budgets raised to their ceilings on the client side so the
core cannot stop emitting first, and so it holds on any buffer size.
