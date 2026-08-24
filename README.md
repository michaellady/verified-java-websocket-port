# verified-java-websocket-port

Evidence-backed safe Rust port of Java-WebSocket.

## Current state

US-001 immutable input intake is implemented but deliberately not marked promoted. Every planned source, standard, suite, macOS toolchain, developer tool, frozen contract, and the exact Autobahn linux/amd64 image was acquired and digest-verified without executing downloaded bytes. The retained vulnerability snapshot found 12 critical and 147 high rules in the mandatory Autobahn image, and no existing-identity signatures or independent approvals have been supplied.

The verifier therefore exits nonzero with `VULNERABILITY_STATE_BLOCKED` and `MISSING_PROMOTION_REQUIREMENT`:

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
