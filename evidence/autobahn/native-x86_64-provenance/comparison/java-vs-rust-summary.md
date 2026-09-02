# Java 1.6.0 vs Rust port, same host, same 247-case manifest

Rust agent `verified-rust-ws-testee-us019`; Java agent `verified-java-websocket-port-1.6.0`.

This is a comparison, not a verdict. AC3 is not ruled on here.

## Server role, `behavior`

- AGREE_NON_STRICT: 13
- AGREE_STRICT: 233
- JAVA_STRICTER: 1

## Server role, `behaviorClose`

- AGREE_NON_STRICT: 3
- AGREE_STRICT: 116
- JAVA_STRICTER: 127
- RUST_STRICTER: 1

## Client role, `behavior`

- AGREE_NON_STRICT: 13
- AGREE_STRICT: 233
- JAVA_STRICTER: 1

## Client role, `behaviorClose`

- AGREE_NON_STRICT: 3
- AGREE_STRICT: 240
- JAVA_STRICTER: 4

## Per-case rows where `behavior` differs

| case | strict required | role | rust | java | direction |
|---|---|---|---|---|---|
| 5.15 | true | server | NON-STRICT | OK | JAVA_STRICTER |
| 5.15 | true | client | NON-STRICT | OK | JAVA_STRICTER |

## Cases where BOTH are non-strict on `behavior`

| case | role | shared outcome |
|---|---|---|
| 3.2 | server | NON-STRICT |
| 3.2 | client | NON-STRICT |
| 3.3 | server | NON-STRICT |
| 3.3 | client | NON-STRICT |
| 4.1.3 | server | NON-STRICT |
| 4.1.3 | client | NON-STRICT |
| 4.1.4 | server | NON-STRICT |
| 4.1.4 | client | NON-STRICT |
| 4.2.3 | server | NON-STRICT |
| 4.2.3 | client | NON-STRICT |
| 4.2.4 | server | NON-STRICT |
| 4.2.4 | client | NON-STRICT |
| 6.4.1 | server | NON-STRICT |
| 6.4.1 | client | NON-STRICT |
| 6.4.2 | server | NON-STRICT |
| 6.4.2 | client | NON-STRICT |
| 6.4.3 | server | NON-STRICT |
| 6.4.3 | client | NON-STRICT |
| 6.4.4 | server | NON-STRICT |
| 6.4.4 | client | NON-STRICT |
| 7.1.6 | server | INFORMATIONAL |
| 7.1.6 | client | INFORMATIONAL |
| 7.13.1 | server | INFORMATIONAL |
| 7.13.1 | client | INFORMATIONAL |
| 7.13.2 | server | INFORMATIONAL |
| 7.13.2 | client | INFORMATIONAL |
