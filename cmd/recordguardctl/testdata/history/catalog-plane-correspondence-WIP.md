# catalog plane correspondence — working notes (WIP)

Task: establish the Codex-plane / Claude-plane correspondence for the crates the
vendored 24-obligation catalog cites, fix the diagnosis `formalcoverctl` emits,
and repair the two failing packages. Started from F006.

## Evidence gathered (all read from the process, none asserted)

### The two planes' Rust workspaces

| Codex directory | Codex `[package] name` | Codex `[lib] name` | Claude directory | Claude `[package] name` | Claude `[lib] name` |
|---|---|---|---|---|---|
| `rust/connection-core` | `websocket-core` | `websocket_core` | `rust/ws-core` | `ws-core` | `ws_core` |
| `rust/websocket-driver` | `websocket-driver` | (default) | `rust/ws-driver` | `ws-driver` | `ws_driver` |
| `rust/websocket-testee` | `websocket-testee` | (default) | `rust/ws-testee` | `ws-testee` | `ws_testee` |

The catalog's namespaces `websocket_core` / `websocket_driver` are the Codex
plane's LIBRARY names, not its directory names. The Codex directory that ships
`websocket_core` is called `connection-core`.

### Shared ancestry

`git merge-base HEAD origin/codex/race-catchup` = `66f33d4` (2026-08-26).
`66f33d4:rust/` contains exactly one crate: `connection-core`, package name
`connection-core`, no `[lib] name` override, with `src/framing.rs`.

- Claude renamed it: `9fe68ff`, git rename detection R097 on `src/lib.rs`.
  Authority: `evidence/governance/decisions/us009-us008-owner-decisions-2026-08-27.json`,
  `us009_crate_naming = ws_core`.
- Codex kept the directory name and set `[lib] name = "websocket_core"`.

### Borrow receipts already record a partial file correspondence

`evidence/governance/decisions/borrow-receipt-batch-{a,b,c}.json` name Codex
`source_path` -> Claude `adapted_path` pairs with source blob shas.

## Status

- [x] plane facts
- [ ] diagnosis fix
- [ ] failing packages
- [ ] RED readings
