# Normalization collision audit — WORK IN PROGRESS

Branch: `claude/normalization-collision-audit`, based on mainline `2c63205`.

## Baseline reproduced (exit codes read from the process)

```
cargo build -p ws-oracle-harness            exit 0
./target/debug/ws-oracle-harness < public-requests.jsonl   exit 0, 74 lines
diffregressctl compare --java evidence/ac5-class-completeness/java-arm-public.jsonl
                        --rust <fresh rust arm>
  total=74 identical=48 detail_only=26 divergent=0 []   exit 0
```

## First structural reading of the record shape

74 public rows fall into exactly two key-sets:

| rows | outcome | keys present |
| --- | --- | --- |
| 48 | `ok` | close, counts, events, final_state, frames, initial_state, outcome, protocol, request_digest, request_id, role, runtime, transitions, version |
| 26 | `error` | counts, error, final_state, outcome, protocol, request_digest, request_id, runtime, version |

`events`, `frames`, `transitions`, `close`, `role` and `initial_state` are
**absent from every error row** — `response.rs::failure_response` never emits
them, mirroring `OracleEngine.failure`. The 26 detail-only rows in the headline
are exactly these 26.

### Refinement of that reading

Of the six dropped keys, `role` and `initial_state` are **request echoes**, not
observations: they are recoverable from `request_digest`, which binds the whole
canonical request and IS compared. So for a FIXED request they carry no
behavioural information and their absence cannot hide a behaviour.

The collision-bearing drops are the four observation streams:
**`events`, `frames`, `transitions`, `close`.**

## The normalization surface, as enumerated so far

Four distinct projections exist on the behaviour side
(`rust/ws-oracle-harness/src/response.rs`):

| projection | keys emitted | what it destroys |
| --- | --- | --- |
| `ok_response` | 14 | intra-observation orderings (see S-05), mask keys (S-06) |
| `failure_response` | 9 | events, frames, transitions, close — ALL observation streams |
| `output_limit_response` | 6 | everything: counts, final_state, AND `runtime` |
| `envelope_error_response` | 5 | `request_id` is literally `null`; no digest binding at all |

And on the handshake side (`handshake_adapter.rs` + `internal/corpora/handshake_live.go`),
the whole scored surface is: `java_observable` ∈ {accept,reject,incomplete},
`reject_channel` (reject only), `close_code` (a CONSTANT 1002), and
`sec_websocket_accept` (server-side accepts only). The entire HTTP response
head is discarded — the adapter says so in its own comment.

Status: WIP, pushed early. Next: constructive probes.
