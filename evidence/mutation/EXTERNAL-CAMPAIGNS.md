# External Rust mutation campaigns

The original US-022 receipt remains an exact historical planted-mutant campaign. These supplemental receipts record the later official `cargo-mutants` campaigns without rewriting that history.

| Subject | Scope | Total | Caught | Missed | Unviable | Timeout | Result |
|---|---:|---:|---:|---:|---:|---:|---|
| `30bbcad` | discovery plus serial timeout replay | 1,005 | 767 | 114 | 123 | 1 | 87.06% of resolved viable mutants caught |
| `38428a5` | deterministic four-shard full campaign | 938 | 786 | 32 | 120 | 0 | 96.09% raw viable score |
| `ac15da8` | blocking-only targeted closure | 9 selected | 9 | 0 | 0 | 0 | all eight live misses plus one paired boundary mutant caught |

The 32 raw misses at `38428a5` were not silently erased. Eight were reachable contract gaps and were closed by test-only commit `ac15da8`. The remaining 24 have explicit algebraic, control-flow, invariant, redundant-guard, unreachable-branch, or allocation-shape witnesses in `external-38428a5/adjudication.json`.

Production Rust logic is unchanged between `38428a5` and `ac15da8`; the closure changes integration tests and one `#[cfg(test)]` source module only. No second full campaign was run after the focused closure, and no Autobahn campaign was rerun.
