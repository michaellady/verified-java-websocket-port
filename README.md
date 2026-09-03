# verified-java-websocket-port

Evidence-backed safe Rust port of Java-WebSocket.

## Current state

US-001 immutable input intake is complete. The repository owner supplied protected authority and signed all four required actions, and the exact 23-object input set was promoted without executing downloaded bytes. The retained vulnerability snapshot found 12 critical and 147 high rules in the mandatory Autobahn image; the accepted disposition confines it to quarantined laboratory qualification.

The frozen `foundation-1.0.0` policy remains byte-for-byte intact. The authoritative `java-websocket-single-owner-1.0.0` amendment permits `github:michaellady` to sign each stage under its required action role. This is an explicit assurance downgrade to `OWNER_ATTESTED_NOT_INDEPENDENT`; it is not independent review.

The resulting receipt is `SINGLE_OWNER_PROMOTED_NO_INDEPENDENT_REVIEW`, with promotion-store root `sha256:5713245496362ece061c769bc4ee8eb909bfcc6d7d319bc3fc9b750f6e0a4ad8`, 23 accepted objects, zero publication actions, and zero protected-access actions. Production use and publication remain unauthorized.

The public verifier still exits nonzero with `OWNER_RISK_DISPOSITION_REQUIRED` and `PROTECTED_CALLER_REQUIRED` because candidate-authored public evidence cannot stand in for protected authority or authorize its own risk disposition:

```sh
go run ./cmd/intakectl verify --evidence-dir evidence/intake
```

Passing unit, race, and vet checks validate both the fail-closed public boundary and the protected promotion transaction. The public receipt contains signed actions and promotion results, while private key material, authoritative role and revocation projections, and the durable nonce ledger remain outside the repository:

```sh
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
```

See [docs/us001-immutable-intake.md](docs/us001-immutable-intake.md) for the evidence and trust boundary.

## US-024 refinement status

US-024 is complete at `603ef0fdd5bb3f114d95b09e7282ee2a74c8e60a`
for the owner-relaxed deterministic-refinement mechanics. The sole mutable
`ConnectionOwner` now delegates its private pending-output and partial-write
lifecycle to a private `OutputLedger`; public declarations and the
`ConnectionCore` contract did not change. The retained replay proves 74/74
normalized public scenarios equal and records 34 local descriptors with 986
before and 1010 after observations. Its V2 evidence build removes path-bearing
debug information, derives the Mach-O UUID with the prior UUID and code-signature
blob zeroed, then ad-hoc signs and strictly verifies the executable. Three
isolated after-subject builds were byte-identical.

The repository receipt remains intentionally pending-only: executed owner
review, QA, and reality provenance is retained outside the repository in HQ
orchestration state. The final receipt digest is
`sha256:3482e63dd0b5e31a244bdc82d5cd491ebeb3c22e5b345b434d709d1d27463853`.
The maximum result is `PASS_OWNER_RELAXED_MECHANICS` under
`OWNER_ATTESTED_NOT_INDEPENDENT` with `independent_review_claimed:false`; it is
not parity `READY` or release readiness.

The eight retained blockers are:

- `AUTOBAHN_AUTHORITY_CONSUMED`
- `HIDDEN_SEALED_NOT_EXECUTED`
- `FORMAL_BACKEND_NOT_EXECUTED`
- `FORMAL_REFINEMENT_DISCONNECTED`
- `CONCURRENCY_DIFFERENT_SUBJECT`
- `INDEPENDENT_HOST_NOT_EXECUTED`
- `INDEPENDENT_HUMAN_REVIEW_NOT_EXECUTED`
- `PRODUCTION_CUTOVER_NOT_AUTHORIZED`

The seven retained nonclaims are:

- no fresh Java differential comparison
- no Autobahn or Docker/wstest rerun
- no hidden or sealed confirmation
- no formal proof or equivalence
- no independent host or human review
- no performance result
- no production, publication, signing, or cutover

See [docs/us024-refinement-contract.md](docs/us024-refinement-contract.md) for
the exact refinement and evidence boundary.

## Docker SBX agent lanes

The repository now carries a blocked, reviewable Docker SBX design for running
the same one-story Java-to-Rust workflow with Muse Code, Codex, or Claude.
Nothing is launched on the installed SBX 0.39 baseline. See
[sbx/README.md](sbx/README.md) for the exact image pins, agent profiles, shared
porting contract, static validation commands, and remaining launch gates.
