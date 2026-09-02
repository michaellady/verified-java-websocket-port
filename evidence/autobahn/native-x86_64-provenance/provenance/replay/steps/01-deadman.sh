#!/bin/bash
# Dead-man switch. Paired with InstanceInitiatedShutdownBehavior=terminate so
# that a controlling agent that dies cannot leave this host billing.
set -euo pipefail
shutdown -h +240 "US-019 provenance re-run dead-man switch" &
sleep 1
echo "DEADMAN_ARMED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat /run/systemd/shutdown/scheduled 2>/dev/null || echo "(no scheduled file; shutdown backgrounded)"
