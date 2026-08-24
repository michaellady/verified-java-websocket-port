# US-001 TDD and reality evidence

## RED

The first test run failed to compile because the strict decoder, canonical signed action, authoritative identity model, nonce ledger, role/stage policy, archive inspector, exact OCI validator, and atomic promoter did not exist. Representative failures were `undefined: DecodeStrict`, `undefined: CanonicalAction`, `undefined: Authorize`, and `undefined: NewMemoryLedger`.

## GREEN

The implemented suite passes:

```text
go test ./... -count=1
?    github.com/michaellady/verified-java-websocket-port/cmd/intakectl [no test files]
ok   github.com/michaellady/verified-java-websocket-port/internal/intake

go test -race ./... -count=1
?    github.com/michaellady/verified-java-websocket-port/cmd/intakectl [no test files]
ok   github.com/michaellady/verified-java-websocket-port/internal/intake

go vet ./...
PASS
```

## Reality checks

- The 23-artifact catalog was downloaded or content-store acquired on 2026-08-24 and byte-counted.
- Java-WebSocket source/archive/JAR/POM/license, RFC 6455, Autobahn source/license/registry, Maven, four Rust distribution objects, JDT LS, rust-analyzer, Glancer, and three frozen repository contracts matched every planned SHA-256 pin.
- Maven additionally matched its published SHA-512.
- The Homebrew OpenJDK bottle matched `sha256:6d51e51e...`; statically extracted `java` and `javac` matched the laboratory binary pins.
- Rust, Maven, JDT LS, rust-analyzer, and Glancer key embedded executable bytes were statically extracted and hashed without execution.
- Docker pulled the exact Autobahn linux/amd64 manifest digest and all 15 layers. The image was never started.
- Docker SBOM 0.6.0 scanned the exact image layers and retained a 460-component CycloneDX document.
- Docker Scout 1.17.1 scanned an archive of the exact image and retained a 48,934,631-byte SARIF snapshot with 740 unique vulnerability rules.
- OSV querybatch returned ten empty result objects; the projection explicitly records incomplete coverage rather than claiming zero vulnerability.

## Expected fail-closed E2E result

`go run ./cmd/intakectl verify --evidence-dir evidence/intake` returns a stable evidence root and exits nonzero with exactly:

- `VULNERABILITY_STATE_BLOCKED`
- `MISSING_PROMOTION_REQUIREMENT`

This is the correct current result. No accepted object, publication action, protected-store access, identity assignment, signature, or risk acceptance was fabricated to make the story green.

## Declared-final review

The single declared-final full-diff review ran in a clean project-only repository against the initial `main` commit with `codex review -c 'model="gpt-5.4"' --base isolated-base`. It found four blocking boundary/durability defects: the durable nonce ledger did not fsync its containing directory, sandbox evidence did not enforce the exact secret/forbidden-access contract, the deferred Linux-host record was parsed but not enforced, and durable promotion did not fsync every mutated directory.

All four were remediated. Targeted regression tests for concurrent nonce consumption, secret/forbidden-access mutation, Linux-deferral mutation, and durable promotion corruption pass, followed by the full unit, race, vet, and expected-blocked E2E gates. Per the project stopping rule, the full diff was not re-reviewed after these bounded fixes.
