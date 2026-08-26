#!/usr/bin/env bash
# run-benchmark.sh — US-008 benchmark-runner STUB (enabling work).
#
# Invoked on the job-scoped confirmation host via SSM by
# .github/workflows/benchmark.yml. This stub does exactly two things:
#   1. validates its arguments (fail-closed), and
#   2. emits the result-schema skeleton with the NOT_MEASURED sentinel in
#      every metric field, plus honestly-captured host identity facts.
#
# It performs NO benchmark, produces NO performance number, and REFUSES any
# mode that implies measurement. Real measured runs require: frozen +
# independently attested plan, bound environments (see
# benchmarks/environments/), bound tool identities with digests, and a
# replacement runner that is itself digest-bound in the preregistration.
# Fabricating a number where a NOT_MEASURED sentinel belongs is a blocking
# integrity violation (see benchmarks/README.md).

set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: run-benchmark.sh --mode pipeline-smoke --pr <N> --workspace bench-pr-<N> --out <dir>

  --mode       Only 'pipeline-smoke' is accepted. Any measurement-implying
               mode is refused by design.
  --pr         Decimal PR number for this job-scoped run.
  --workspace  Must equal bench-pr-<pr> (the job-scoped workspace contract).
  --out        Writable output directory for the result-schema skeleton.
EOF
  exit 2
}

mode="" pr="" workspace="" out=""
while [ $# -gt 0 ]; do
  case "$1" in
    --mode)      mode="${2:-}"; shift 2 ;;
    --pr)        pr="${2:-}"; shift 2 ;;
    --workspace) workspace="${2:-}"; shift 2 ;;
    --out)       out="${2:-}"; shift 2 ;;
    -h|--help)   usage ;;
    *) echo "error: unknown argument '$1'" >&2; usage ;;
  esac
done

[ -n "$mode" ] && [ -n "$pr" ] && [ -n "$workspace" ] && [ -n "$out" ] || {
  echo "error: --mode, --pr, --workspace, and --out are all required" >&2
  usage
}

if [ "$mode" != "pipeline-smoke" ]; then
  echo "error: mode '$mode' refused. This runner is a stub: only 'pipeline-smoke' exists, and no mode may produce measurements until the preregistration binds a real, digest-bound runner." >&2
  exit 3
fi

case "$pr" in
  ''|*[!0-9]*) echo "error: --pr must be a decimal PR number (got '$pr')" >&2; exit 2 ;;
esac

if [ "$workspace" != "bench-pr-${pr}" ]; then
  echo "error: --workspace must equal bench-pr-${pr} (got '$workspace')" >&2
  exit 2
fi

mkdir -p "$out"

# Honest host-identity capture: these are REAL probe outputs from the host we
# are running on (useful when the owner later binds
# benchmarks/environments/confirmation.json). They are identity facts, not
# benchmark measurements.
kernel="$(uname -sr 2>/dev/null || echo NOT_MEASURED)"
arch="$(uname -m 2>/dev/null || echo NOT_MEASURED)"
os_pretty="NOT_MEASURED"
if [ -r /etc/os-release ]; then
  os_pretty="$(. /etc/os-release && echo "${PRETTY_NAME:-NOT_MEASURED}")"
fi
timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

emit_workload() {
  # $1 = workload id. Every metric is the NOT_MEASURED sentinel: this stub
  # never measures, and no number may ever be invented here.
  cat <<EOF
    {
      "workload": "$1",
      "samples": "NOT_MEASURED",
      "peak_rss": "NOT_MEASURED",
      "steady_rss": "NOT_MEASURED",
      "cpu_time": "NOT_MEASURED",
      "startup_to_ready": "NOT_MEASURED",
      "latency_p50": "NOT_MEASURED",
      "latency_p95": "NOT_MEASURED",
      "latency_p99": "NOT_MEASURED",
      "allocated_bytes": "NOT_MEASURED",
      "allocation_count": "NOT_MEASURED",
      "throughput": "NOT_MEASURED"
    }
EOF
}

result="${out}/pipeline-smoke-result.json"
{
  cat <<EOF
{
  "schema": "vjwp-bench-pipeline-smoke/1",
  "mode": "pipeline-smoke",
  "honesty": "STUB OUTPUT — this is a pipeline plumbing check, not a benchmark. Every metric is the NOT_MEASURED sentinel by design. This artifact is not evidence for US-008 and asserts no performance claim.",
  "pr_number": "${pr}",
  "workspace": "${workspace}",
  "generated_at_utc": "${timestamp}",
  "host_identity_probe": {
    "note": "Real identity facts from the host this stub ran on (not measurements).",
    "kernel": "${kernel}",
    "architecture": "${arch}",
    "os": "${os_pretty}"
  },
  "workloads": [
EOF
  emit_workload "wl-01-handshake-close"; echo ","
  emit_workload "wl-02-small-text-echo"; echo ","
  emit_workload "wl-03-fragmented-64kib-binary-echo"; echo ","
  emit_workload "wl-04-control-mix"; echo ","
  emit_workload "wl-05-cap-rejection"; echo ","
  emit_workload "wl-06-concurrent-pressure"
  cat <<'EOF'
  ]
}
EOF
} > "$result"

# Self-check: the emitted artifact must be valid JSON and must contain no
# numeric metric values (defense against future edits fabricating numbers).
if command -v python3 >/dev/null 2>&1; then
  python3 - "$result" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    doc = json.load(f)
metrics = ("samples","peak_rss","steady_rss","cpu_time","startup_to_ready",
           "latency_p50","latency_p95","latency_p99","allocated_bytes",
           "allocation_count","throughput")
for wl in doc["workloads"]:
    for m in metrics:
        if wl[m] != "NOT_MEASURED":
            sys.exit(f"integrity violation: {wl['workload']}.{m} is not the NOT_MEASURED sentinel")
print("self-check ok: valid JSON, all metric fields are NOT_MEASURED sentinels")
PY
else
  echo "warning: python3 unavailable; JSON self-check skipped" >&2
fi

echo "wrote ${result}"
