# A finished record — the differential closed at 4a2b9c6

STATUS: COMPLETE for what it claims.

This record is hand-written and exists for ONE reason. The finding this tool was built from
quotes the div05 stub verbatim, and in a record with a normal line width the closing delimiter
lands on the NEXT line: `*"STATUS: IN PROGRESS — stub pushed early to survive container
restarts. … Nothing verified yet."*`. A masker that pairs delimiters within a single line
reads the trailing fragment as this record's own voice and refuses a finished record. That is
not hypothetical — it happened to this tool's own record, which was refused at exit 1 with a
`void-self-report` signal before the masker learned to carry an open delimiter across a line
break.

The same wrap in double quotes, and again with a typographic pair: "STATUS: IN PROGRESS —
nothing verified yet" and “no findings yet, to be filled in — this is a
quotation”. Both must stay masked.

## Validation, exit codes read from the process

- `go test ./cmd/recordguardctl/` exit 0; `make -C rust record-guard` exit 0.
- The observed differential is bounded by the corpus; sha256 4a2b9c6f1e2d3c4b5a69788899aabbcc.
