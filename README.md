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
