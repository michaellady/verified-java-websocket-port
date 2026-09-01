#!/bin/bash
# Cloud environment setup for the verified Java -> Rust WebSocket port.
#
# HOW THIS IS USED: paste the contents of this file into the "Setup script"
# field of the environment dialog at claude.ai/code. Cloud setup scripts are
# configured in that dialog, not read from the repository -- this file is kept
# in the repo so the script is reviewable, diffable, and does not live only in
# a web form.
#
# The script runs as root on Ubuntu 24.04 before Claude Code launches, and only
# when no cached environment exists. Three constraints shape everything below:
#   1. It must exit zero, or the session fails to start.
#   2. It should finish inside five minutes, or the environment cache cannot
#      build and every new session pays the cost again.
#   3. Package installs need network. The default "Trusted" access level covers
#      crates.io, GitHub and the other registries used here.
#
# WHAT IS ALREADY PRESENT, and therefore deliberately not installed:
#   OpenJDK 21 with Maven and Gradle, Docker with compose, Go, git, gh, jq,
#   ripgrep. OpenJDK 21 is sufficient for java-oracle, which sets
#   maven.compiler.release 17 -- a release target, not a JDK requirement.
#
# WHAT THIS SCRIPT ADDS, and why it is not optional:
#   Rust 1.95.0 via rustup. The pin is not stylistic. rust/rust-toolchain.toml
#   says "do not float this channel", and cmd/rustgatectl's msrv gate FAILS
#   HARD rather than skipping when that toolchain is absent from rustup:
#   "build-under-MSRV is a hard requirement and cannot execute, so the gate
#   FAILS rather than passing pending". A session carrying only the
#   pre-installed rustc cannot pass `make -C rust gates`.

set -uo pipefail

echo "=== verified-java-websocket-port cloud setup ==="
echo "started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Rust and Go go into shared prefixes rather than root's home, because this
# script runs as root while the session may not. World-readable prefixes plus a
# profile.d entry keep both on PATH for every user.
export RUSTUP_HOME=/usr/local/rustup
export CARGO_HOME=/usr/local/cargo
RUST_CHANNEL=1.95.0
GO_VERSION=1.25.5

install_rust() {
  echo "--- rust ${RUST_CHANNEL} ---"
  local rustup_bin
  if command -v rustup >/dev/null 2>&1; then
    rustup_bin="$(command -v rustup)"
  else
    # --default-toolchain none keeps this step to just the rustup binary, so
    # the pinned toolchain is installed by exactly one code path below.
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --no-modify-path --profile minimal --default-toolchain none
    rustup_bin="${CARGO_HOME}/bin/rustup"
  fi
  if [ ! -x "${rustup_bin}" ]; then
    echo "ERROR: rustup is not available at ${rustup_bin}"
    return 1
  fi
  # --component here takes a COMMA-separated list. The space-separated form
  # would be parsed as a second TOOLCHAIN NAME, not as a component, and would
  # fail trying to install a toolchain called "clippy". Verified against
  # `rustup toolchain install --help`, which reads:
  #   -c, --component <COMPONENT>  Comma-separated list of components
  # (`rustup component add` is the one that takes space-separated values.)
  "${rustup_bin}" toolchain install "${RUST_CHANNEL}" --profile minimal --component rustfmt,clippy
  "${rustup_bin}" default "${RUST_CHANNEL}" 2>/dev/null || true
}

install_go() {
  echo "--- go ${GO_VERSION} ---"
  # go.mod requires go 1.25. If the pre-installed Go already satisfies that,
  # leave it alone rather than spending the time budget on a second copy.
  local have
  have="$(go version 2>/dev/null | awk '{print $3}' | sed 's/^go//')"
  if [ -n "${have}" ] && [ "$(printf '%s\n1.25\n' "${have}" | sort -V | head -1)" = "1.25" ]; then
    echo "pre-installed go ${have} satisfies go.mod (>= 1.25); skipping"
    return 0
  fi
  echo "pre-installed go '${have:-none}' does not satisfy >= 1.25; installing ${GO_VERSION}"
  local arch tarball
  case "$(uname -m)" in
    x86_64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) echo "unknown arch $(uname -m); leaving go as-is"; return 0 ;;
  esac
  tarball="go${GO_VERSION}.linux-${arch}.tar.gz"
  curl -fsSL "https://go.dev/dl/${tarball}" -o "/tmp/${tarball}" || return 0
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "/tmp/${tarball}" || return 0
  rm -f "/tmp/${tarball}"
}

# The two installs are independent, so run them concurrently to stay inside the
# five-minute budget. Both return zero even on a failed non-essential step; a
# genuine Rust failure is reported by the verification block below rather than
# aborting here, so a session still starts and can be diagnosed interactively.
install_rust &
RUST_PID=$!
install_go &
GO_PID=$!
wait "${RUST_PID}" || echo "WARNING: rust install returned non-zero"
wait "${GO_PID}"   || echo "WARNING: go install returned non-zero"

# PATH for every subsequent shell, including the one Claude Code runs in.
cat >/etc/profile.d/vjwp-toolchains.sh <<'PROFILE'
export RUSTUP_HOME=/usr/local/rustup
export CARGO_HOME=/usr/local/cargo
export PATH="/usr/local/cargo/bin:/usr/local/go/bin:${PATH}"
PROFILE
chmod 0644 /etc/profile.d/vjwp-toolchains.sh
export PATH="/usr/local/cargo/bin:/usr/local/go/bin:${PATH}"

# Readable and executable by non-root users; the session may not run as root.
chmod -R a+rX /usr/local/rustup /usr/local/cargo 2>/dev/null || true

# Warm the cargo registry cache. The workspace ships zero non-path
# dependencies, so this is quick -- which is why it is worth doing here rather
# than paying it on the first build inside the session.
if [ -f rust/Cargo.toml ]; then
  (cd rust && cargo fetch --locked) || echo "note: cargo fetch skipped or failed (non-fatal)"
fi

# Verification. Read the real versions rather than assuming the installs did
# what they claimed. A setup script that reports success while leaving the MSRV
# toolchain absent produces a session whose gates cannot pass, and that failure
# would surface much later and much less clearly.
echo "=== verification ==="
echo "rustup:  $(rustup --version 2>&1 | head -1 || echo MISSING)"
echo "rustc:   $(rustc --version 2>&1 || echo MISSING)"
echo "cargo:   $(cargo --version 2>&1 || echo MISSING)"
echo "fmt:     $(cargo fmt --version 2>&1 || echo MISSING)"
echo "clippy:  $(cargo clippy --version 2>&1 || echo MISSING)"
echo "go:      $(go version 2>&1 || echo MISSING)"
echo "java:    $(java -version 2>&1 | head -1 || echo MISSING)"
echo "mvn:     $(mvn --version 2>&1 | head -1 || echo MISSING)"
echo "docker:  $(docker --version 2>&1 || echo MISSING)"

if rustup toolchain list 2>/dev/null | grep -q "^${RUST_CHANNEL}"; then
  echo "OK: MSRV toolchain ${RUST_CHANNEL} is installed via rustup, so the msrv gate can execute"
else
  echo "WARNING: MSRV toolchain ${RUST_CHANNEL} is NOT installed via rustup."
  echo "         cmd/rustgatectl's msrv gate will FAIL, not skip."
  echo "         Recover inside the session with:"
  echo "           rustup toolchain install ${RUST_CHANNEL} --component rustfmt clippy"
fi

echo "finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
# Exit zero unconditionally. A non-zero exit prevents the session from starting
# at all, which is strictly worse than a session that starts with a diagnosable
# toolchain problem printed above.
exit 0
