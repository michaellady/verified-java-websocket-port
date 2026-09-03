#!/usr/bin/env bash
#
# Deterministic replay for J1: obligation `surface.close.status-code`, JAVA,
# BOUNDED_MODEL. Runs BOTH canaries and fails unless each lands on its
# expected side.
#
#   known-good : unmutated declarative spec  -> expect exit 0,  VERIFICATION SUCCESSFUL
#   known-bad  : spec mutated to drop the    -> expect exit 10, VERIFICATION FAILED
#                legal close code 1000           with counterexample code=1000
#
# A canary nobody watched fail is not a canary, so this script treats a
# known-bad run that PASSES as a hard error.
#
# Usage:  bash assurance/formal/java/replay-j1.sh
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CBMC_LIB="${CBMC_LIB:-/opt/homebrew/Cellar/cbmc/6.11.0/libexec/lib}"
CORE_MODELS="${CBMC_LIB}/core-models.jar"
CPROVER_API="${CBMC_LIB}/cprover-api.jar"

SRC_ROOT="${REPO_ROOT}/.quarantine/Java-WebSocket-da3cf2a777aed862f2f5b5cf060cae7969958667/src/main/java"
HARNESS="${REPO_ROOT}/assurance/formal/java/harness/CloseStatusCodeHarness.java"
BUILD="${REPO_ROOT}/.quarantine/build"
PROPERTY='java::CloseStatusCodeHarness.check:()V.assertion.1'

ARCHIVE_SHA256="f44e7647b4aee40819b51947cf0bb5f35a48293a202b77704c3c79e98ed13cb4"
JBMC_SHA256="a3cb2f3be91b2aa8bef9e75862f51afd1a369058813a0e6f4a6b9fdc99906cb1"
CORE_MODELS_SHA256="7ae8884b36ec598d44541d8a7f19f059ed282ebce812d23a1473e66b357d101e"

fail() { echo "REPLAY FAILED: $*" >&2; exit 1; }

echo "=== J1 replay: surface.close.status-code / JAVA / BOUNDED_MODEL ==="

# ---- 0. Trusted computing base identity -------------------------------------
command -v jbmc >/dev/null || fail "jbmc not on PATH"
[ -f "${CORE_MODELS}" ] || fail "core-models.jar not found at ${CORE_MODELS}"
[ -d "${SRC_ROOT}" ] || fail "quarantined source root not extracted at ${SRC_ROOT}"

got_jbmc="$(shasum -a 256 "$(command -v jbmc)" | awk '{print $1}')"
[ "${got_jbmc}" = "${JBMC_SHA256}" ] || fail "jbmc sha256 ${got_jbmc} != pinned ${JBMC_SHA256}"
got_models="$(shasum -a 256 "${CORE_MODELS}" | awk '{print $1}')"
[ "${got_models}" = "${CORE_MODELS_SHA256}" ] || fail "core-models.jar sha256 ${got_models} != pinned ${CORE_MODELS_SHA256}"
got_archive="$(shasum -a 256 "${REPO_ROOT}/.quarantine/java-websocket-source-archive.tar.gz" | awk '{print $1}')"
[ "${got_archive}" = "${ARCHIVE_SHA256}" ] || fail "source archive sha256 ${got_archive} != pinned ${ARCHIVE_SHA256}"

jbmc --version
javac -version 2>&1

# ---- 1. Compile the shipped CloseFrame dependency closure -------------------
rm -rf "${BUILD}/j1-classes" "${BUILD}/bad-classes" "${BUILD}/bad-src"
mkdir -p "${BUILD}/j1-classes" "${BUILD}/bad-classes" "${BUILD}/bad-src"

javac -nowarn -d "${BUILD}/j1-classes" -cp "${CPROVER_API}" -sourcepath "${SRC_ROOT}" \
  "${SRC_ROOT}/org/java_websocket/framing/CloseFrame.java" || fail "shipped-source compile failed"
javac -nowarn -d "${BUILD}/j1-classes" -cp "${CPROVER_API}:${BUILD}/j1-classes" \
  "${HARNESS}" || fail "harness compile failed"

# ---- 2. KNOWN-GOOD canary ---------------------------------------------------
echo
echo "--- canary A (known-good): unmutated spec, expect VERIFICATION SUCCESSFUL ---"
( cd "${BUILD}/j1-classes" && jbmc CloseStatusCodeHarness \
    --function 'CloseStatusCodeHarness.check' \
    --classpath ".:${CORE_MODELS}" \
    --property "${PROPERTY}" ) > "${BUILD}/j1-good.txt" 2>&1
good_exit=$?
tail -6 "${BUILD}/j1-good.txt"
[ "${good_exit}" -eq 0 ] || fail "known-good canary exit ${good_exit}, expected 0"
grep -q "VERIFICATION SUCCESSFUL" "${BUILD}/j1-good.txt" || fail "known-good canary did not report VERIFICATION SUCCESSFUL"
grep -q "0 of 1 failed" "${BUILD}/j1-good.txt" || fail "known-good canary did not report 0 of 1 failed"

# ---- 3. KNOWN-BAD canary ----------------------------------------------------
# Mutation: drop the legal close code 1000 from the declarative sendable set,
# so the spec wrongly demands that CloseFrame.isValid() reject 1000.
echo
echo "--- canary B (known-bad): spec drops legal code 1000, expect VERIFICATION FAILED ---"
sed 's/if (code >= 1000 && code <= 1003) {/if (code >= 1001 \&\& code <= 1003) {/' \
  "${HARNESS}" > "${BUILD}/bad-src/CloseStatusCodeHarness.java"
grep -q "code >= 1001 && code <= 1003" "${BUILD}/bad-src/CloseStatusCodeHarness.java" \
  || fail "mutation did not apply; the known-bad canary would be a no-op"

cp -R "${BUILD}/j1-classes/org" "${BUILD}/bad-classes/"
javac -nowarn -d "${BUILD}/bad-classes" -cp "${CPROVER_API}:${BUILD}/bad-classes" \
  "${BUILD}/bad-src/CloseStatusCodeHarness.java" || fail "mutant compile failed"

( cd "${BUILD}/bad-classes" && jbmc CloseStatusCodeHarness \
    --function 'CloseStatusCodeHarness.check' \
    --classpath ".:${CORE_MODELS}" \
    --property "${PROPERTY}" \
    --trace ) > "${BUILD}/j1-bad.txt" 2>&1
bad_exit=$?
tail -6 "${BUILD}/j1-bad.txt"
[ "${bad_exit}" -eq 10 ] || fail "known-bad canary exit ${bad_exit}, expected 10 -- the canary did not discriminate"
grep -q "VERIFICATION FAILED" "${BUILD}/j1-bad.txt" || fail "known-bad canary did not report VERIFICATION FAILED"
grep -q "1 of 1 failed" "${BUILD}/j1-bad.txt" || fail "known-bad canary did not report 1 of 1 failed"
grep -q "to_return=1000" "${BUILD}/j1-bad.txt" \
  || fail "known-bad counterexample did not minimize to close code 1000"

echo
echo "=== J1 replay OK: known-good SUCCESSFUL (exit 0), known-bad FAILED (exit 10, code=1000) ==="
echo "=== observed strength: BoundedCheckPassed (NOT ProofEstablished) ==="
