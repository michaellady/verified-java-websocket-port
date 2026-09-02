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
  `-D warnings`, debug and release tests, the eight AC1 gates, and since
  `ledger-integrity` landed the `ledger-gates` target, which needs
  `VJWP_PROTECTED_STORE` exported and treats an unreachable store as a failure.
- The Go suite: `go build ./...` passes; `go test ./...` passes except for
  three packages that fail on Linux for environment reasons, listed under
  "Known environment failures" below. Read those per package.
- The Java oracle: the pinned Java-WebSocket 1.6.0 jar and its SLF4J API come
  from Maven Central; the adapter builds, self-tests, and scores the public
  tier and the handshake exam here. See "Running the corpus differential and
  the handshake exam here" below for the exact commands and the UTF-8 flag.
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

## Running the corpus differential and the handshake exam here

Both are `corporactl` invocations, and every `corporactl` command regenerates
the corpora from a protected root that must hold
`us005-corpora/secrets/master-secret.hex`. That secret lives in HQ, not in this
repository. The public and handshake tiers do not depend on it: the generator
derives them from the committed public seed alone and uses the secret only for
the hidden and sealed tiers (`internal/corpora/generate.go`), and on 2026-09-02
the requests generated from two different throwaway secrets were
byte-identical, with the handshake request digest
`e00d968f0ae623dd75a09842ad435642c0dca53ee5e9f9ef654ce26c1f814c49` matching the
batch-B receipt. So a throwaway secret is sound for those two tiers and for
nothing else: never run the hidden or sealed tiers against one, and never
present a run made this way as a custodian-ledgered result.

```
S=/tmp/vjwp-protected; mkdir -p $S/us005-corpora/secrets
python3 -c 'import secrets; print(secrets.token_hex(32))' > $S/us005-corpora/secrets/master-secret.hex
go run ./cmd/corporactl oracle-requests --root . --protected-root $S --tier public --out public.jsonl
go run ./cmd/corporactl oracle-requests --root . --protected-root $S --tier handshake --wire --out handshake.jsonl
cargo build --release --manifest-path rust/Cargo.toml -p ws-oracle-harness --locked
rust/target/release/ws-oracle-harness < public.jsonl > public-rust.jsonl
go run ./cmd/corporactl evaluate --root . --protected-root $S --tier public --transcript public-rust.jsonl
rust/target/release/ws-oracle-harness < handshake.jsonl > handshake-rust.jsonl
go run ./cmd/corporactl evaluate --root . --protected-root $S --tier handshake --live --transcript handshake-rust.jsonl
```

The handshake `evaluate --live` on the port's raw transcript fails all 49 on
the runtime pin, by design: the transcript names `ws-oracle-harness` as its
runtime. The recorded exam neutralises that one field to the accepted Java
runtime and its digest before scoring, exactly as
`drafts/us010-us011-handshake-exam/transcript-rust-runtime-neutralized.jsonl`
does; nothing else is touched.

The live Java oracle runs here too. Materialise the pinned runtime jar and its
SLF4J API from their immutable Maven Central URLs into `.quarantine/` (ignored
by git), verify the jar against the intake digest, build the adapter, and run
it with UTF-8 standard output. Without that flag the JVM's `stdout.encoding`
follows the unset locale and every non-ASCII text payload is written as `?`,
which showed up as nine spurious public-tier failures.

```
curl -sSfL -o .quarantine/Java-WebSocket-1.6.0.jar https://repo1.maven.org/maven2/org/java-websocket/Java-WebSocket/1.6.0/Java-WebSocket-1.6.0.jar
curl -sSfL -o .quarantine/slf4j-api-2.0.13.jar https://repo1.maven.org/maven2/org/slf4j/slf4j-api/2.0.13/slf4j-api-2.0.13.jar
sha256sum .quarantine/Java-WebSocket-1.6.0.jar   # eae29213e4f16515639c28957200f011b3967fffcada1962cf0255d24919c22f
make -C java-oracle test JAVA_WEBSOCKET_JAR=$PWD/.quarantine/Java-WebSocket-1.6.0.jar RUNTIME_SUPPORT_CP=$PWD/.quarantine/slf4j-api-2.0.13.jar
java -Dstdout.encoding=UTF-8 -Dslf4j.internal.verbosity=ERROR -cp java-oracle/build/java-oracle.jar:.quarantine/Java-WebSocket-1.6.0.jar:.quarantine/slf4j-api-2.0.13.jar OracleMain < public.jsonl > public-java.jsonl
```

SLF4J 2.0.13 is the version the pinned runtime's own POM declares. Its digest
`e7c2a48e8515ba1f49fa637d57b4e2f590b3f5bd97407ac699c3aa5efb1204a9` is the
US-002-qualified value that `java-semantic-oracle/Makefile` and
`internal/portplan` enforce before javac runs; it is not in `source-pins.json`.

Results read on 2026-09-02 in this environment, harness sha256
`414d7e5b85c8ef8b7de2a32ebbdad824cae0d82f7d332514325e705d4a90adb9`:

| Run | Result |
| --- | --- |
| Public tier, port | 74/74 |
| Public tier, live Java | 74/74 with UTF-8 stdout; 65/74 without it |
| Port vs live Java, public transcripts | only the free-text error detail differs; every other field agrees on all 74 |
| Handshake exam, port, neutralised runtime | 49/49, 16 documented divergences |
| Handshake exam, live Java | 49/49, the same 16 divergences |
| Port vs live Java, handshake transcripts | no non-runtime field differs on any of the 49 |
| java-oracle self-test | 18 pass |

## Pinned Java inputs: how to materialise them here

Four inputs live under `.quarantine/` (ignored by git). The setup script
stages them into `~/.cache/verified-java-websocket-port/quarantine/`; copy
that directory to `.quarantine/` at the start of a session, or fetch them by
hand as below. Every one is digest-verified against a pin before use, here and
again by the code that consumes it.

| Input | Source | Pin |
| --- | --- | --- |
| `Java-WebSocket-1.6.0.jar` | Maven Central immutable URL | sha256 `eae29213…c22f`, 140686 bytes, `evidence/intake/source-pins.json` |
| `slf4j-api-2.0.13.jar` | Maven Central immutable URL | sha256 `e7c2a48e…04a9`, the US-002-qualified digest enforced by `java-semantic-oracle/Makefile` and `internal/portplan` |
| `java-websocket-source-archive.tar.gz` | reproduced from an anonymous clone | sha256 `f44e7647…3cb4`, 190008 bytes, `evidence/intake/source-pins.json` |
| `jdk-17.0.19+10/` | Temurin release asset | sha256 `d8afc263…d331`, 193335385 bytes, the pin Codex's `cmd/cloudsetup` carries |

The archive's immutable URL returns HTTP 403 through the session proxy, which
serves anonymous git reads of public repositories but not their archive
downloads. GitHub builds those archives with `git archive` and gzip level 6,
so the bytes are reproducible from the pinned commit:

```
git clone --depth 1 https://github.com/TooTallNate/Java-WebSocket /tmp/jws
git -C /tmp/jws fetch --depth 1 origin da3cf2a777aed862f2f5b5cf060cae7969958667
git -C /tmp/jws archive --format=tar --prefix=Java-WebSocket-da3cf2a777aed862f2f5b5cf060cae7969958667/ da3cf2a777aed862f2f5b5cf060cae7969958667 \
  | gzip -n -6 > .quarantine/java-websocket-source-archive.tar.gz
sha256sum .quarantine/java-websocket-source-archive.tar.gz   # f44e7647b4aee40819b51947cf0bb5f35a48293a202b77704c3c79e98ed13cb4
```

Verified 2026-09-02: git's built-in `--format=tar.gz` and gzip levels 1 and 9
do not match the pin; `gzip -n -6` does. `internal/portplan` verifies the
digest before extracting, so a reproduced archive is exactly as trustworthy as
a downloaded one.

The JDK pin matters because `internal/portplan` regenerates the semantic-id
oracle report with the `javac` found on `PATH` and refuses any version but
17.0.19:

```
curl -sSfL -o /tmp/jdk17.tar.gz 'https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.19%2B10/OpenJDK17U-jdk_x64_linux_hotspot_17.0.19_10.tar.gz'
sha256sum /tmp/jdk17.tar.gz   # d8afc263758141a66e0e3aafc321e783f7016696f4eaea067d340a269037d331
tar -xzf /tmp/jdk17.tar.gz -C .quarantine        # creates .quarantine/jdk-17.0.19+10
export PATH=$PWD/.quarantine/jdk-17.0.19+10/bin:$PATH
```

## Known environment failures in `go test ./...`

`go build ./...` passes. With the inputs above in place, the protected store
exported, and the pinned JDK first on `PATH`, 29 packages pass and two fail for
environment reasons. Each failure is a typed finding, never a skip. Read them
per package; do not treat the suite as green, and do not treat these as
project failures.

- `internal/lab`: `PLATFORM_EXECUTOR_UNSUPPORTED`, the controlled canary
  requires Darwin `sandbox-exec`. Linux cannot satisfy it.
- `internal/portplan`, `TestDeriveReproducesCommittedEvidence`:
  `ORACLE_REPRODUCTION_MISMATCH`. The check byte-compares the regenerated
  semantic-id oracle report with the committed one, and the committed report
  embeds `"jdk_vendor": "Homebrew"`. On 2026-09-02 the Linux Temurin 17.0.19
  regeneration differed in that one line only, reading `"Eclipse Adoptium"`;
  all 969 declarations, the totals, and the javac options were identical. So
  the check can pass byte-for-byte only on a Homebrew OpenJDK host. Making it
  vendor-agnostic, or pinning the vendor as an explicit host requirement, is an
  owner decision on intake evidence; it is recorded in the goal loop and not
  changed here.

Two more things read as failures only when something is missing:

- `VJWP_PROTECTED_STORE` must be exported for `go test` as well as for
  `make -C rust gates`. Otherwise twelve `internal/deltaledger` tests refuse
  with THE PROTECTED GOVERNANCE STORE IS NOT REACHABLE, which is that gate's
  design, not a defect.
- Without the pinned JDK first on `PATH`, `internal/portplan` fails earlier
  with `JAVAC_UNAVAILABLE` naming the image's javac 21.0.10.
