# US-019 native provenance re-run — run notes

Attempt `us019-prov-20260828T183623Z`. Authorized by the owner decision recorded at
`workspace/orchestrator/verified-java-websocket-port-claude/protected/us019-native-provenance-and-ac3-owner-decision-2026-08-28.json`.

This tree is additive. The earlier `evidence/autobahn/native-x86_64/` run is untouched
and remains readable alongside it.

## What this run was for

The earlier native x86_64 run genuinely executed; that was established and is not in
question. What it never captured was the provenance AC1 and AC5 name: image digest,
source identity, process identities, resource limits and replay commands. Those cannot
be reconstructed after the fact, so the capture is wired into each leg here, before the
sweep it describes.

## Host

One `c7i.xlarge`, instance `i-0fd462789e9e80548`, AMI `ami-02b3d83d84b07786d`,
`us-east-1a`, Intel Xeon Platinum 8488C, kernel `6.1.180-225.360.amzn2023.x86_64`,
`uname -m = x86_64`. Launched 18:44:56Z, terminated 18:54:23Z. Booted-host facts were
read through IMDSv2 into `host/us008-booted-host-facts.json`.

All four legs ran on this one host against this one 247-case manifest
(`autobahn/case-manifest.json`, sha256 `27243d52…`, re-verified on the host). Same host
and same manifest is what makes the Java-versus-Rust comparison load-bearing rather
than indicative.

## The five provenance artifacts

| artifact | where | status |
|---|---|---|
| image digest | `provenance/image-digest.json` | present; `invoked_by_form = MANIFEST_DIGEST`, `digest_binding.bound = true` |
| source identity | `provenance/source-identity.json` | present; commit `518b77aa…`, payload digest matched on arrival |
| process identities | `provenance/*/subject-process.json` | present for all four legs; argv, pid, ppid, absolute start time, exe digest |
| resource limits | `provenance/*/harness-container.json` | present, and **unbounded** — see the gap below |
| replay commands | `provenance/replay/` | present; all eleven step scripts with their digests |

Process identities were captured while each process was alive
(`liveness.status = OBSERVED`). Container limits were read from **inside** the running
container, not from the launch command: `docker exec … cat /proc/1/limits` and the
cgroup v2 interface files.

Process environments were deliberately not captured. They can carry credentials and no
criterion asks for them; `environ` is recorded as `ABSENT` with that reason rather than
silently omitted.

## Gap to flag: AC1's "bounded resources" clause is NOT met

The resource limits are captured truthfully, and what they show is that the run was
**not** resource-bounded. Read from inside the running harness container:

- `memory.max` = `max`
- `memory.high` = `max`
- `cpu.max` = `max 100000`
- `pids.max` = `9279`
- pid 1 rlimits: cpu time, file size, data size, address space all `unlimited`

No `--memory`, `--cpus` or `--ulimit` was passed to any container, and no rlimit was
imposed on either subject. So AC1's *"by manifest digest"* clause is met and its
*"with bounded resources"* clause is not. That is recorded here as an unmet criterion
rather than dressed up: an honest gap is worth more than a manufactured envelope, which
is the principle this whole re-run exists to serve.

## Deviations, recorded rather than smoothed over

**1. The Java fuzzingserver leg needed a recovery invocation.** The endpoint walked all
247 cases and then failed on its final `/updateReports` connection with
`ENDPOINT_DENIED report update did not connect: timeout without endpoint error`. The
endpoint's own 45-second per-connection timeout expires waiting for a close the suite's
report endpoint does not send promptly. Since `/updateReports` is what writes
`index.json`, the leg re-invoked the endpoint with `--case-count 1`, which completed
(`CLIENT_COMPLETE`) and emitted the index for every case the server session already
held. Consequence: **in that leg case 1's report comes from the recovery invocation,
not the original walk.** Same binary, same host, same session; recorded so a reader is
not surprised by it. Both invocations are logged, at `java/fuzzingserver-run1/agent.log`
and `agent-recovery.log`.

**2. The Java fuzzingclient spec is derived, in exactly two fields.** From the pinned
`autobahn/fuzzingclient.json` (sha256 `68dc019c…`), the derivation changes the agent
name to `verified-java-websocket-port-1.6.0` and the port to `9011`, and nothing else.
The one-line diff is in the build log; both files are in `config/`. A distinct port was
used so the Java listener could not collide with the Rust listener's sockets in
`TIME_WAIT`.

**3. The Java endpoint's fixed Host authority was preflighted, not assumed.** The
endpoint pins its Host header to `172.30.242.4:9001` and refuses any other value, while
its URL gate refuses anything but a bare loopback origin. Those are satisfiable together
only by publishing the port on loopback and sending the fixed authority as a header. The
suite's acceptance of that header was probed against the live server before the sweep;
the probe is at `java/fuzzingserver-run1/host-header-preflight.txt`.

## Two digest manifests, on purpose

`digest-manifest-as-produced-on-host.json` is the manifest the host wrote over the
1036 files it packaged, and it was re-verified on this workstation after transfer: every
file that came off the host matched, with the only findings being the nine artifacts
added afterwards. `digest-manifest.json` covers the assembled tree of 1046 files,
including the comparison, the run notes, the AWS records and the tooling sources, and
verifies clean. Keeping both separates "what left the host" from "what is committed".

## Reconciliation exit status

All four `reconcile` invocations exited 1. That is the AC3 strict-pass gate firing, not
a failure to reconcile: every leg reports `reconciles=true` with all identities
satisfied, and every leg reports `strict_pass_all=false`. The gate now fires on the Java
baseline too, on the same cases.

## What this run does not do

It does not rule on AC3. It produces the same-host, same-manifest comparison the owner
ordered so that the question can be decided on evidence. The comparison is at
`comparison/java-vs-rust-summary.md` and `comparison/java-vs-rust-per-case.json`, and
the comparison tool emits no verdict field by construction.
