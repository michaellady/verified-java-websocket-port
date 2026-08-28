# US-023 immutable parity coverage

Snapshot: **FROZEN**  
Parity: **BLOCKED**  
Candidate root: `sha256:628d1bc67c0fcc421bf04b25d0a5d0ccedb218f529f47ef052a10e9f5ec60bb4`  
Evaluation root: `sha256:1ce17436e979b0b563e9224992cb1e12c67b37e2d15d9be9cf62253a52b82969`

## Original gates

| Gate | Criterion | Observed | Blockers |
| --- | --- | --- | --- |
| `gate.ac1.darwin-arm64` | AC-1 | BLOCKED | blocker-gate-not-executed, blocker-platform-darwin |
| `gate.ac1.linux-arm64` | AC-1 | BLOCKED | blocker-gate-not-executed, blocker-platform-linux |
| `gate.ac1.java-build` | AC-1 | BLOCKED | blocker-gate-not-executed |
| `gate.ac1.java-62-tests` | AC-1 | BLOCKED | blocker-gate-not-executed |
| `gate.ac1.rust-debug-build` | AC-1 | BLOCKED | blocker-gate-not-executed |
| `gate.ac1.rust-release-build` | AC-1 | BLOCKED | blocker-gate-not-executed |
| `gate.ac1.rust-tests` | AC-1 | BLOCKED | blocker-gate-not-executed |
| `gate.ac1.rust-fmt` | AC-1 | BLOCKED | blocker-gate-not-executed |
| `gate.ac1.rust-clippy` | AC-1 | BLOCKED | blocker-gate-not-executed |
| `gate.ac1.go-tests` | AC-1 | BLOCKED | blocker-gate-not-executed |
| `gate.ac1.go-vet` | AC-1 | BLOCKED | blocker-gate-not-executed |
| `gate.ac1.unsafe` | AC-1 | BLOCKED | blocker-gate-not-executed |
| `gate.ac1.dependencies` | AC-1 | BLOCKED | blocker-gate-not-executed |
| `gate.ac1.licenses` | AC-1 | BLOCKED | blocker-gate-not-executed |
| `gate.ac1.vulnerabilities` | AC-1 | BLOCKED | blocker-gate-not-executed |
| `gate.ac1.lockfile` | AC-1 | BLOCKED | blocker-gate-not-executed |
| `gate.ac1.no-stub` | AC-1 | BLOCKED | blocker-gate-not-executed |
| `gate.ac1.source-membership` | AC-1 | BLOCKED | blocker-gate-not-executed |
| `gate.ac1.test-membership` | AC-1 | BLOCKED | blocker-gate-not-executed |
| `gate.ac1.zero-silent-skip` | AC-1 | BLOCKED | blocker-gate-not-executed |
| `gate.ac1.test-reconciliation` | AC-1 | BLOCKED | blocker-gate-not-executed |
| `gate.ac2.rfc` | AC-2 | BLOCKED | blocker-gate-not-executed |
| `gate.ac2.autobahn` | AC-2 | BLOCKED | blocker-autobahn-authority, blocker-current-rust-autobahn, blocker-gate-not-executed |
| `gate.ac2.handshake` | AC-2 | BLOCKED | blocker-gate-not-executed |
| `gate.ac2.differential` | AC-2 | BLOCKED | blocker-gate-not-executed |
| `gate.ac2.property` | AC-2 | BLOCKED | blocker-gate-not-executed |
| `gate.ac2.fuzz` | AC-2 | BLOCKED | blocker-gate-not-executed |
| `gate.ac2.runtime` | AC-2 | BLOCKED | blocker-gate-not-executed |
| `gate.ac2.formal` | AC-2 | BLOCKED | blocker-formal-backend, blocker-gate-not-executed |
| `gate.ac2.concurrency` | AC-2 | BLOCKED | blocker-gate-not-executed |
| `gate.ac2.mutation` | AC-2 | BLOCKED | blocker-gate-not-executed |
| `gate.ac2.hidden` | AC-2 | BLOCKED | blocker-current-rust-protected, blocker-gate-not-executed, blocker-protected-control |
| `gate.ac2.sealed` | AC-2 | BLOCKED | blocker-current-rust-protected, blocker-gate-not-executed, blocker-protected-control |
| `gate.ac3.denominator` | AC-3 | BLOCKED | blocker-formal-backend, blocker-gate-not-executed |
| `gate.ac3.java-bindings` | AC-3 | BLOCKED | blocker-gate-not-executed, blocker-java-source |
| `gate.ac3.rust-bindings` | AC-3 | BLOCKED | blocker-formal-refinement, blocker-gate-not-executed |
| `gate.ac3.refinement` | AC-3 | BLOCKED | blocker-formal-refinement, blocker-gate-not-executed |
| `gate.ac3.mutation-sensitivity` | AC-3 | BLOCKED | blocker-formal-refinement, blocker-gate-not-executed |
| `gate.ac4.content-dag` | AC-4 | BLOCKED | blocker-gate-not-executed |
| `gate.ac4.git-bindings` | AC-4 | BLOCKED | blocker-gate-not-executed |
| `gate.ac4.deterministic-replay` | AC-4 | BLOCKED | blocker-gate-not-executed |
| `gate.ac5.codex-review` | AC-5 | BLOCKED | blocker-gate-not-executed, blocker-sole-owner |
| `gate.ac5.human-review` | AC-5 | BLOCKED | blocker-gate-not-executed, blocker-human-review |
| `gate.ac5.independent-host` | AC-5 | BLOCKED | blocker-gate-not-executed, blocker-independent-host, blocker-sole-owner |

## Evidence families

| Family | Observed | Current Rust | Findings | Divergences |
| --- | --- | --- | ---: | ---: |
| RFC | BLOCKED | RETAINED_DIFFERENT_SUBJECT | 0 | 0 |
| AUTOBAHN | BLOCKED | RETAINED_DIFFERENT_SUBJECT | 0 | 0 |
| HANDSHAKE | BLOCKED | RETAINED_DIFFERENT_SUBJECT | 0 | 0 |
| DIFFERENTIAL | BLOCKED | RETAINED_DIFFERENT_SUBJECT | 0 | 0 |
| PROPERTY | BLOCKED | RETAINED_DIFFERENT_SUBJECT | 0 | 0 |
| FUZZ | BLOCKED | RETAINED_DIFFERENT_SUBJECT | 0 | 0 |
| RUNTIME | BLOCKED | RETAINED_DIFFERENT_SUBJECT | 0 | 0 |
| FORMAL | BLOCKED | DISCONNECTED | 0 | 0 |
| CONCURRENCY | BLOCKED | RETAINED_DIFFERENT_SUBJECT | 0 | 0 |
| MUTATION | BLOCKED | RETAINED_DIFFERENT_SUBJECT | 0 | 0 |
| HIDDEN | BLOCKED | RETAINED_DIFFERENT_SUBJECT | 0 | 0 |
| SEALED | BLOCKED | RETAINED_DIFFERENT_SUBJECT | 0 | 0 |

## Formal obligations

| Obligation | Java | Rust | Refinement | Mutation | Aggregate |
| --- | --- | --- | --- | --- | --- |
| `obligation.checked-header-arithmetic` | BLOCKED | BLOCKED | BLOCKED | BLOCKED | BLOCKED |
| `obligation.control-fin-and-length` | BLOCKED | BLOCKED | BLOCKED | BLOCKED | BLOCKED |
| `obligation.length-canonical-16` | BLOCKED | BLOCKED | BLOCKED | BLOCKED | BLOCKED |
| `obligation.length-canonical-64-high-bit-zero` | BLOCKED | BLOCKED | BLOCKED | BLOCKED | BLOCKED |
| `obligation.length-canonical-7` | BLOCKED | BLOCKED | BLOCKED | BLOCKED | BLOCKED |
| `obligation.mask-equation` | BLOCKED | BLOCKED | BLOCKED | BLOCKED | BLOCKED |
| `obligation.mask-involution` | BLOCKED | BLOCKED | BLOCKED | BLOCKED | BLOCKED |
| `obligation.preallocation-cap` | BLOCKED | BLOCKED | BLOCKED | BLOCKED | BLOCKED |
| `obligation.role-masking` | BLOCKED | BLOCKED | BLOCKED | BLOCKED | BLOCKED |
| `surface.adapter.byte-stream` | BLOCKED | BLOCKED | BLOCKED | BLOCKED | BLOCKED |
| `surface.close.status-code` | BLOCKED | BLOCKED | BLOCKED | BLOCKED | BLOCKED |
| `surface.close.terminal-state` | BLOCKED | BLOCKED | BLOCKED | BLOCKED | BLOCKED |
| `surface.concurrency.command-order` | BLOCKED | BLOCKED | BLOCKED | BLOCKED | BLOCKED |
| `surface.control.ping-pong` | BLOCKED | BLOCKED | BLOCKED | BLOCKED | BLOCKED |
| `surface.errors.protocol-fault` | BLOCKED | BLOCKED | BLOCKED | BLOCKED | BLOCKED |
| `surface.fragmentation.continuation` | BLOCKED | BLOCKED | BLOCKED | BLOCKED | BLOCKED |
| `surface.handshake.client-request` | BLOCKED | BLOCKED | BLOCKED | BLOCKED | BLOCKED |
| `surface.handshake.server-response` | BLOCKED | BLOCKED | BLOCKED | BLOCKED | BLOCKED |
| `surface.messages.binary` | BLOCKED | BLOCKED | BLOCKED | BLOCKED | BLOCKED |
| `surface.messages.text-utf8` | BLOCKED | BLOCKED | BLOCKED | BLOCKED | BLOCKED |

## Typed blockers

| Blocker | Code | Subject |
| --- | --- | --- |
| `blocker-autobahn-authority` | `AUTOBAHN_AUTHORITY_CONSUMED_NO_RERUN` | retained-autobahn-authority |
| `blocker-current-rust-autobahn` | `CURRENT_RUST_AUTOBAHN_NOT_EXECUTED` | shipped-rust |
| `blocker-current-rust-protected` | `CURRENT_RUST_PROTECTED_NOT_EXECUTED` | shipped-rust |
| `blocker-formal-backend` | `FORMAL_BACKEND_UNAVAILABLE` | formal-backends |
| `blocker-formal-refinement` | `FORMAL_REFINEMENT_DISCONNECTED` | shipped-rust |
| `blocker-gate-not-executed` | `GATE_NOT_EXECUTED` | candidate |
| `blocker-human-review` | `HUMAN_REVIEW_NOT_EXECUTED` | human-review |
| `blocker-independent-host` | `INDEPENDENT_HOST_UNAVAILABLE` | independent-host |
| `blocker-java-source` | `JAVA_SOURCE_OBJECT_UNAVAILABLE` | java-source-archive |
| `blocker-platform-darwin` | `BLOCKING_PLATFORM_NOT_EXECUTED` | darwin/arm64 |
| `blocker-platform-linux` | `BLOCKING_PLATFORM_NOT_EXECUTED` | linux/arm64 |
| `blocker-protected-control` | `PROTECTED_CONTROL_NOT_EXECUTED` | protected-control |
| `blocker-sole-owner` | `SOLE_OWNER_NOT_INDEPENDENT` | owner |

## Nonclaims

- `NO_CUTOVER`
- `NO_CUTOVER_READY`
- `NO_CURRENT_RUST_CONTROL_HIDDEN_EXECUTION`
- `NO_CURRENT_RUST_CONTROL_SEALED_EXECUTION`
- `NO_INDEPENDENT_REVIEW`
- `NO_LIVE_AUTOBAHN_RERUN`
- `NO_PERFORMANCE_RESULT`
- `NO_PRODUCTION`
- `NO_PROTECTED_CASE_ACCESS`
- `NO_PUBLICATION`
- `NO_SIGNING`
- `NO_UNAVAILABLE_TOOL_PASS`
