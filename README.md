# verified-java-websocket-port

Evidence-backed safe Rust port of Java-WebSocket.

## Current state

US-001 immutable input intake is implemented but deliberately not marked promoted. Every planned source, standard, suite, macOS toolchain, developer tool, frozen contract, and the exact Autobahn linux/amd64 image was acquired and digest-verified without executing downloaded bytes. The retained vulnerability snapshot found 12 critical and 147 high rules in the mandatory Autobahn image, and the repository owner's protected authority and signatures have not been supplied.

The frozen `foundation-1.0.0` policy remains byte-for-byte intact. The authoritative `java-websocket-single-owner-1.0.0` amendment permits `github:michaellady` to sign each stage under its required action role. This is an explicit assurance downgrade to `OWNER_ATTESTED_NOT_INDEPENDENT`; it is not independent review.

The public verifier therefore exits nonzero with `OWNER_RISK_DISPOSITION_REQUIRED` and `MISSING_PROMOTION_REQUIREMENT`:

```sh
go run ./cmd/intakectl verify --evidence-dir evidence/intake
```

Passing unit, race, and vet checks validate the fail-closed machinery; they do not override the external attestation gate:

```sh
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
```

See [docs/us001-immutable-intake.md](docs/us001-immutable-intake.md) for the evidence and trust boundary.
