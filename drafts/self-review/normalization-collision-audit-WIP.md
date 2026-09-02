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

Status: WIP, pushed early.
