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
#   The four pinned Java inputs the Go suites and the live Java oracle need,
#   staged under ~/.cache/verified-java-websocket-port/quarantine/ and
#   digest-verified: the Java-WebSocket 1.6.0 jar, its SLF4J API, the upstream
#   source archive (reproduced with git archive, since the session proxy
#   refuses GitHub archive downloads), and the Temurin JDK 17.0.19+10 that
#   internal/portplan requires. Copy that directory to .quarantine/ in a
#   session. See CLOUD-ENVIRONMENT.md, "Pinned Java inputs".

set -uo pipefail

echo "=== verified-java-websocket-port cloud setup ==="
echo "started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Rust goes into rustup's DEFAULT home (root's ~/.rustup and ~/.cargo), not a
# shared prefix. The session runs as root too, and its shell carries
# RUSTUP_HOME=/root/.rustup in the environment the harness hands it, which
# overrides anything /etc/profile.d exports. An earlier revision of this script
# installed into /usr/local/rustup: the toolchain landed there correctly and
# the session never saw it (verified 2026-09-02 -- `rustup toolchain list`
# showed only the pre-installed stable until cargo's first run under
# rust-toolchain.toml made rustup install 1.95.0 on demand, which needs network
# at session time and hides the setup failure). Do NOT export RUSTUP_HOME or
# CARGO_HOME here.
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
    rustup_bin="${HOME:-/root}/.cargo/bin/rustup"
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

# Pinned Java inputs, staged outside the checkout because the checkout is
# cloned fresh per session. Every file is verified against its pin here, and
# again by the code that consumes it, so a partial or corrupted download is
# discarded rather than kept. Nothing here is fatal.
STAGE="${HOME:-/root}/.cache/verified-java-websocket-port/quarantine"
fetch_pinned() { # url dest sha256
  if [ -f "$2" ] && [ "$(sha256sum "$2" | cut -c1-64)" = "$3" ]; then echo "present: $(basename "$2")"; return 0; fi
  if ! curl -sSfL -o "$2.part" "$1"; then echo "WARNING: fetch failed: $1"; rm -f "$2.part"; return 0; fi
  if [ "$(sha256sum "$2.part" | cut -c1-64)" = "$3" ]; then mv "$2.part" "$2"; echo "verified: $(basename "$2")"
  else echo "WARNING: digest mismatch, discarded: $1"; rm -f "$2.part"; fi
}
stage_java_inputs() {
  echo "--- pinned java inputs -> ${STAGE} ---"
  mkdir -p "${STAGE}"
  fetch_pinned https://repo1.maven.org/maven2/org/java-websocket/Java-WebSocket/1.6.0/Java-WebSocket-1.6.0.jar \
    "${STAGE}/Java-WebSocket-1.6.0.jar" eae29213e4f16515639c28957200f011b3967fffcada1962cf0255d24919c22f
  fetch_pinned https://repo1.maven.org/maven2/org/slf4j/slf4j-api/2.0.13/slf4j-api-2.0.13.jar \
    "${STAGE}/slf4j-api-2.0.13.jar" e7c2a48e8515ba1f49fa637d57b4e2f590b3f5bd97407ac699c3aa5efb1204a9
  # GitHub builds source archives with `git archive` and gzip level 6, so the
  # pinned archive is reproduced from an anonymous shallow clone and checked
  # against evidence/intake/source-pins.json. Verified byte-exact 2026-09-02.
  local sha=da3cf2a777aed862f2f5b5cf060cae7969958667
  local pin=f44e7647b4aee40819b51947cf0bb5f35a48293a202b77704c3c79e98ed13cb4
  local archive="${STAGE}/java-websocket-source-archive.tar.gz"
  if [ -f "${archive}" ] && [ "$(sha256sum "${archive}" | cut -c1-64)" = "${pin}" ]; then
    echo "present: java-websocket-source-archive.tar.gz"
  else
    local clone; clone="$(mktemp -d)"
    if git clone -q --depth 1 https://github.com/TooTallNate/Java-WebSocket "${clone}/jws" \
       && git -C "${clone}/jws" fetch -q --depth 1 origin "${sha}"; then
      git -C "${clone}/jws" archive --format=tar --prefix="Java-WebSocket-${sha}/" "${sha}" | gzip -n -6 > "${archive}.part"
      if [ "$(sha256sum "${archive}.part" | cut -c1-64)" = "${pin}" ]; then
        mv "${archive}.part" "${archive}"; echo "verified: java-websocket-source-archive.tar.gz (reproduced)"
      else echo "WARNING: reproduced archive digest mismatch, discarded"; rm -f "${archive}.part"; fi
    else echo "WARNING: could not clone the pinned upstream to reproduce the archive"; fi
    rm -rf "${clone}"
  fi
  # Temurin JDK 17.0.19+10: internal/portplan refuses any other javac version.
  local jdk="${STAGE}/OpenJDK17U-jdk_x64_linux_hotspot_17.0.19_10.tar.gz"
  fetch_pinned 'https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.19%2B10/OpenJDK17U-jdk_x64_linux_hotspot_17.0.19_10.tar.gz' \
    "${jdk}" d8afc263758141a66e0e3aafc321e783f7016696f4eaea067d340a269037d331
  if [ -f "${jdk}" ] && [ ! -x "${STAGE}/jdk-17.0.19+10/bin/javac" ]; then
    tar -xzf "${jdk}" -C "${STAGE}" || echo "WARNING: jdk extract failed"
  fi
}

# The installs are independent, so run them concurrently to stay inside the
# five-minute budget. All return zero even on a failed non-essential step; a
# genuine Rust failure is reported by the verification block below rather than
# aborting here, so a session still starts and can be diagnosed interactively.
install_rust &
RUST_PID=$!
install_go &
GO_PID=$!
stage_java_inputs &
JAVA_PID=$!
wait "${RUST_PID}" || echo "WARNING: rust install returned non-zero"
wait "${GO_PID}"   || echo "WARNING: go install returned non-zero"
wait "${JAVA_PID}" || echo "WARNING: java input staging returned non-zero"

# PATH for login shells. The session shell already carries /root/.cargo/bin
# and /usr/local/go/bin; this entry only matters for a shell that does not.
cat >/etc/profile.d/vjwp-toolchains.sh <<'PROFILE'
export PATH="${HOME:-/root}/.cargo/bin:/usr/local/go/bin:${PATH}"
PROFILE
chmod 0644 /etc/profile.d/vjwp-toolchains.sh
export PATH="${HOME:-/root}/.cargo/bin:/usr/local/go/bin:${PATH}"

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
echo "rustup home: $(rustup show home 2>&1 || echo MISSING)  (the session's rustup reads RUSTUP_HOME=/root/.rustup)"
echo "rustc:   $(rustc --version 2>&1 || echo MISSING)"
echo "cargo:   $(cargo --version 2>&1 || echo MISSING)"
echo "fmt:     $(cargo fmt --version 2>&1 || echo MISSING)"
echo "clippy:  $(cargo clippy --version 2>&1 || echo MISSING)"
echo "go:      $(go version 2>&1 || echo MISSING)"
echo "java:    $(java -version 2>&1 | head -1 || echo MISSING)"
echo "mvn:     $(mvn --version 2>&1 | head -1 || echo MISSING)"
echo "docker:  $(docker --version 2>&1 || echo MISSING)"
echo "staged java inputs: $(ls "${STAGE}" 2>/dev/null | tr '\n' ' ')"
echo "jdk17:   $("${STAGE}/jdk-17.0.19+10/bin/javac" -version 2>&1 | grep -v JAVA_TOOL_OPTIONS || echo MISSING)"

if rustup toolchain list 2>/dev/null | grep -q "^${RUST_CHANNEL}"; then
  echo "OK: MSRV toolchain ${RUST_CHANNEL} is installed via rustup, so the msrv gate can execute"
else
  echo "WARNING: MSRV toolchain ${RUST_CHANNEL} is NOT installed via rustup."
  echo "         cmd/rustgatectl's msrv gate will FAIL, not skip."
  echo "         Recover inside the session with:"
  echo "           rustup toolchain install ${RUST_CHANNEL} --component rustfmt,clippy"
fi

echo "finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
# Exit zero unconditionally. A non-zero exit prevents the session from starting
# at all, which is strictly worse than a session that starts with a diagnosable
# toolchain problem printed above.
exit 0
