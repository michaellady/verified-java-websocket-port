# Pin candidate adjudication (IN PROGRESS — 40/85 read)

Detector `go run ./cmd/pinconsumerctl dangling -root .` — exit 1 read from process.
1996 JSON artifacts, 0 unparsable, 85 candidates.

## Resolved so far
- 25 rows `$.engines[0].toolchain` -> `rust/rust-toolchain.toml`: FALSE POSITIVE.
  `pin_digest` is `TreeDigest([pin_file])`, a `path\x00filedigest\n` envelope, not raw bytes.
- 1 row `toolchain-pin-drift.json`: FALSE POSITIVE, deliberate negative fixture.
- 14 rows `assurance/fuzz/campaign/result.json`: FALSE POSITIVE, `outcome_digest`
  covers the in-object `outcome_lines`, verified for all 14.

45 candidates still unread.
