# F016 — the gate a criterion names cannot detect what the criterion promises

## The criterion

`docs/prd-pack/07b-child-prd-us009-us019.md:118`, US-018 AC1's third bullet:

> A linkage test proves the adapters call the exact shipped core/driver symbols
> and **a seeded adapter-side parser or protocol branch fails the architecture
> gate.**

That is a testable promise about a specific gate, and it names two things: a
parser branch, and a **protocol branch**.

## The gate

`cmd/rustgatectl/adapter_linkage.go`. Its own header says "adapter-side parser or
protocol branch must fail this gate". Its forbidden list is:

```go
// forbiddenProtocolBranch are parser-shaped patterns: opcode/payload-length
// bitmasks and WebSocket/HTTP wire literals.
var forbiddenProtocolBranch = []string{
	"& 0x0f", "& 0x0F", "& 0x7f", "& 0x7F", "& 0x80",
	"0x0f &", "0x0F &", "0x7f &", "0x7F &", "0x80 &",
	"Sec-WebSocket", "HTTP/1.1", "101 Switching",
}
```

Thirteen entries: five payload-length and opcode bitmasks, their five mirrored
forms, and three wire literals. Every one is **parser-shaped**. Nothing in the
list detects a branch on protocol STATE.

## The proof

I seeded exactly what the criterion says must fail — an adapter-side decision
keyed on core protocol state — into `rust/ws-testee/src/io_loop.rs`:

```rust
fn seeded_protocol_branch(state: ReadyState, role: Role) -> u8 {
    match (role, state) {
        (Role::Server, ReadyState::Closing) => 8,
        (Role::Client, ReadyState::Open) => 1,
        (_, ReadyState::Closed) => 0,
        _ => 2,
    }
}
```

`Role` and `ReadyState` are core types — `rust/ws-core/src/connection.rs:73` and
`:99` — imported by the adapter at `io_loop.rs:14`. This is a protocol branch by
any reading.

Before and after are IDENTICAL:

```
gate=adapter-linkage verdict=PASS detail="adapter linkage exact over 5 production
  sources; edges exact; no protocol surface or parser branch"
ac1-gates verdict=PASS gates_passed=8/8      exit 0
```

**The gate asserts in its own detail string that there is no protocol branch,
while one sits in the file it just scanned.** Restored byte-identically,
`diff -q` clean.

## What this is and is not

It is NOT a claim that `server_closes_transport(role, state)` — the real function
at `io_loop.rs:567` — violates AC1. That is a separate question, it is genuinely
arguable, and it is not settled here.

It IS a claim about the gate: AC1's third bullet is the reason a reader trusts
that no protocol logic has leaked into the adapters, and the gate it names
delivers on "parser" and not on "protocol branch". Whatever the answer about
`server_closes_transport`, the criterion's guarantee is not being enforced.

## How I got here, because the route matters

A sweep agent reported the real function as an AC1 violation, and offered as its
sharpest evidence that two comments "cannot both stand":
`server.rs:47-49` says close behaviour is deliberately not mirrored in the
adapter and cites AC1; `io_loop.rs:563-566` says which endpoint hangs up is
transport policy and belongs to the adapter.

**That evidence is weaker than it was presented as.** The two comments
distinguish close PROTOCOL from transport FIN, coherently, and the second one
states the distinction explicitly and cites Java's own split (I/O helper versus
`Draft_6455`). They can both stand.

I then formed a counter-argument — the architecture gate passes, so the project
has already adjudicated this shape as acceptable — and **that was also wrong**,
which is the actual finding. The gate does not pass because it considered role
and state branching and allowed it. It passes because it never looks.

Two plausible readings, one from an agent and one from me, both resting on the
gate meaning something it does not mean. The seeded probe is what settled it, and
neither reading would have.

## The fix, and why it is not free

Extend the gate to detect adapter production code branching on core protocol
state types. That makes AC1's third bullet true.

It also, on this tree, immediately implicates `server_closes_transport` — which
is precisely the open question above. So the fix turns the gate red on shipped
code pending a decision that has not been made. The pattern already used twice in
this repository fits: detect the shape, then DECLARE the one known instance with
the owner action it waits on, so a NEW leak fails on the run it appears while the
open question does not halt the loop.

## Status

Filed with the proof. The detector and its declared instance are the next unit;
the AC1 reading for `server_closes_transport` remains an owner question, and this
finding deliberately does not decide it.
