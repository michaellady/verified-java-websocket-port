# Vendor-agnostic oracle reproduction in `internal/portplan`

STATUS: COMPLETE. The comparison is vendor-agnostic, both directions are proven
by running the real test process and reading its exit code, the committed
`evidence/intake/semantic-id-oracle.json` is byte-identical to what it was
before I touched it, and the `cmd/gosuitectl` exclusion for `internal/portplan`
is removed in the same commit as the fix.

Branch `claude/jdk-vendor-agnostic`, cut from `6a155a3`. Worktree
`/home/user/vjwp-jdkvendor` with `.quarantine` symlinked to the staged tree.

## The ruling being implemented

The owner ruled the reproduction check vendor-agnostic. This record implements
that ruling; it does not re-argue it.

## RED baseline, read from the process

Environment: `export VJWP_PROTECTED_STORE=$PWD/evidence/governance/decisions`
and `export PATH=$PWD/.quarantine/jdk-17.0.19+10/bin:$PATH`, with
`javac -version` reporting `javac 17.0.19` (the pinned Temurin 17.0.19+10 in
quarantine; `release` says `IMPLEMENTOR="Eclipse Adoptium"`). Run detached,
exit code written to a file by the run itself.

`go test -count=1 -timeout 40m -run TestDeriveReproducesCommittedEvidence ./internal/portplan/`
exited **1**:

```
--- FAIL: TestDeriveReproducesCommittedEvidence (4.35s)
    e2e_test.go:118: Derive: ORACLE_REPRODUCTION_MISMATCH: the pinned javac regenerates a report that differs from ../../evidence/intake/semantic-id-oracle.json; differing_lines=1 of committed_lines=1071; line 6: committed "  \"jdk_vendor\": \"Homebrew\",", regenerated "  \"jdk_vendor\": \"Eclipse Adoptium\","
FAIL
FAIL	github.com/michaellady/verified-java-websocket-port/internal/portplan	4.372s
```

The whole package, same environment, also exited **1** with that as its ONLY
failing test. So the exclusion's stated reason was accurate and complete on this
host, once the pinned JDK is first on `PATH`: one line of 1071, all 969
declarations identical.

## The comparison, and why it is this narrow

`internal/portplan/reproduce.go`, `VerifyOracleReproduction`, previously ran
`bytes.Equal(regenerated, committed)`. It now neutralises exactly one field in
BOTH reports and compares every remaining byte.

`jdk_vendor` is `System.getProperty("java.vendor")` of whichever build of the
pinned JDK ran the oracle — `java-semantic-oracle/src/main/java/SemanticIdOracle.java`
line 163 emits it, one field per line. It is host provenance. `jdk_version` is
`17.0.19` on both hosts and is NOT excluded.

`neutralizeJDKVendor` splits on newlines and rewrites only lines matching

```
^([ \t]*"jdk_vendor"[ \t]*:[ \t]*)"(?:[^"\\]|\\.)*"(,?)[ \t]*$
```

replacing the JSON string value with a fixed placeholder and returning the value
it replaced plus how many such lines it found. Three properties matter, and each
one is what keeps this from becoming a loose compare:

1. It is **line-count preserving**, so a report that gained or lost a line still
   differs and `describeOracleMismatch` still prints true line numbers.
2. It is **line-shaped, not substring-shaped**. A declaration whose `name` is
   literally `jdk_vendor` is not on a line of that shape and is still compared
   byte for byte.
3. It is **one field**, not one object. The header block around it —
   `tool_version`, `identity_source`, `jdk_version`, `javac_options`, the whole
   `compilation` and `totals` objects — is untouched.

The vendor field stays bound AS A FIELD. Excluding a value is not the same as
tolerating its absence, so a count other than exactly one in either report is
refused by name:

```
ORACLE_VENDOR_FIELD_UNREADABLE: the vendor-agnostic comparison requires exactly
one "jdk_vendor" line in each report so that it knows what it is excluding;
committed <path> has 0, the regenerated report has 1
```

And when some OTHER line differs while the vendor also differs, the mismatch
message discloses the exclusion so the reader is not left wondering whether it
swallowed something:

```
; (jdk_vendor is excluded from this comparison by owner decision and is not
among the differences above: committed "Homebrew", regenerated "Eclipse Adoptium")
```

## Direction 1 — vendor-only difference PASSES

`go test -count=1 -timeout 40m -v ./internal/portplan/` exited **0**.
`--- PASS: TestDeriveReproducesCommittedEvidence (5.60s)`; package line
`ok  github.com/michaellady/verified-java-websocket-port/internal/portplan 10.195s`.
70 tests PASS, 0 FAIL, 1 SKIP. The skip is
`TestMigrationMapDeclaresNoRustWorkspaceExists` ("a Rust workspace now exists;
US-009 has landed and this guard changes shape") — pre-existing, unrelated to
this change, and present in the RED run too.

The regenerated report is produced by the real `make -C java-semantic-oracle run`
against the digest-verified quarantined source, so the PASS is a genuine
Temurin-vs-Homebrew reproduction, not a fixture.

## Direction 2 — any OTHER single line still FAILS

Each case mutates the COMMITTED report on disk, runs the real test detached,
records the exit code, then restores from a pristine copy under a `trap`.

**Case A, one of the 969 declarations.** Changed exactly one character of one
`semantic_key`, `org.java_websocket.WebSocket#close()V` to `#close()Z`, leaving
the vendor line alone so the vendor difference is ALSO present. Exit **1**:

```
ORACLE_REPRODUCTION_MISMATCH: ... differing_lines=1 of committed_lines=1071;
line 219: committed "    {\"semantic_key\": \"org.java_websocket.WebSocket#close()Z\", ... }",
regenerated "    {\"semantic_key\": \"org.java_websocket.WebSocket#close()V\", ... }";
(jdk_vendor is excluded from this comparison by owner decision and is not among
the differences above: committed "Homebrew", regenerated "Eclipse Adoptium")
```

`differing_lines=1`, not 2 — the vendor line is excluded, the declaration line is
not, and the message names the exact line number and the exact declaration.

**Case B, `jdk_vendor` ABSENT rather than different.** Deleted the whole
`  "jdk_vendor": "Homebrew",` line. Exit **1** with
`ORACLE_VENDOR_FIELD_UNREADABLE ... committed ... has 0, the regenerated report
has 1`. This is the third bullet of the task answered by measurement rather than
by argument: absence is caught, and it is caught as its own typed refusal rather
than as a generic mismatch.

**Case C, a `files[]` digest.** Changed one hex character of
`AbstractWebSocket.java`'s recorded sha256. Exit **1**, caught EARLIER at
`ORACLE_TREE_MISMATCH` by `verifyOracleMatchesTree`, which compares the oracle's
file digests against the real tree before the reproduction check runs. Recorded
because it shows the ordering: file-level tampering never reaches the comparison
I changed.

**Restoration.** `sha256sum -c` on
`ee8d39fa71d804218ef41889f5a93e13a0aab85c988879448721e35250da3767  evidence/intake/semantic-id-oracle.json`
→ `OK`, exit **0**. `diff -q` against the pristine copy → silent, exit **0**.
`git status --porcelain -- evidence/` → empty. The committed report was NOT
regenerated at any point; the fix is entirely in the comparison.

## Permanent tests, so the exclusion cannot silently widen

`internal/portplan/vendor_agnostic_test.go` (all PASS, in the exit-0 run above):

- `TestVendorOnlyDifferenceCompareEqualAfterNeutralization` — the real committed
  report with only the vendor line changed compares equal, and the replaced
  value is still READ (`Homebrew` / `Eclipse Adoptium`) so the message can name it.
- `TestAnyOtherSingleLineDifferenceIsStillCaught` — a declaration change beside a
  vendor change still differs, reports `differing_lines=1`, names `close()Z`, and
  does NOT mention `jdk_vendor` among the differences.
- `TestNeighbouringHeaderFieldsAreNotExcluded` — `jdk_version`, `tool_version`,
  the `declarations` total and a `physical_lines` count each still differ. This
  is the guard against the exclusion drifting from one field to "the provenance
  block".
- `TestVendorFieldAbsenceAndAmbiguityAreVisible` — 0 and 2 occurrences are both
  counted, so neither can be silently normalised.
- `TestVendorMatcherIsLineShapedNotSubstring` — a declaration merely NAMED
  `jdk_vendor` is untouched.
- `TestNeutralizationPreservesLineCount` — the newline count is unchanged.

`TestReproductionMismatchNamesWhatActuallyDiffers` and the other two
`describeOracleMismatch` tests are unchanged and still pass. That helper's LOGIC
is untouched — only what is fed to it changed — but its doc comment claimed "the
check above is a whole-file byte compare ... including a single host-provenance
line", which my change made false. It now says what is actually true of both its
callers, because a stale comment beside a corrected check is the same defect in a
quieter place.

## The exclusion, removed in the same commit

`cmd/gosuitectl/main.go`'s `excluded` map carried `internal/portplan` with the
`jdk_vendor` reason. `TestEveryDeclaredExclusionStillFails` and the gate's
`EXCLUSION_NO_LONGER_FAILS` finding both exist so a package that has been FIXED
cannot keep its exemption, so the entry is deleted in the same commit as the
fix. `internal/lab` remains, for Darwin `sandbox-exec`. The file's own prose
said "Two packages genuinely cannot pass on this host"; it now says one, and
records why the second left, so the count and the list cannot disagree.

`.claude/GOAL-LOOP.md` carried the same two-package claim in five places (step 4's
baseline paragraph, the `cmd/gosuitectl` description, the worktree/`.quarantine`
note, the pinned-JDK note, and the P0 board entry plus the US-003 owner-action
column). All are corrected to what is now measured, with the superseded wording
explained rather than deleted.

## What I did NOT verify

- **macOS.** Every reading here is Linux with Temurin 17.0.19+10. I did not run
  the Homebrew-bottle side; the claim that it compares equal rests on the vendor
  line being the only difference, which is the RED measurement above, not a
  separate Darwin run.
- **`internal/lab`.** Still excluded, still unrun by me. I did not test its
  exclusion reason.
- **Whether `jdk_vendor` could ever carry semantic weight.** The ruling says it
  does not; I checked that `SemanticIdOracle.java` uses `java.vendor` only for
  this one output line and nowhere in the identity computation, but I did not
  audit javac itself for vendor-conditional symbol-table behaviour.
- **Other consumers of the oracle bytes.** `internal/linkage` pins the
  MIGRATION MAP's bytes, and `TestDeriveReproducesCommittedEvidence` still
  byte-compares all six derived documents including
  `semantic-id-migration-map.json` with no exclusion at all, so those freezes are
  untouched. I confirmed that by reading, not by mutating the map.
- **A deletion attack on the new comparison.** I proved the mutation directions
  on the DATA. I did not additionally delete the neutralisation and re-measure,
  because the RED baseline above IS that reading: the code before my change is
  the code with the neutralisation removed, and it exits 1 on a vendor-only
  difference.

## Gates

Run detached, exit code read from a file the run itself writes, never from a pipe
and never from a terminal scroll.

**Run 1, commit `ba0dac9`** (the fix, the tests and the exclusion removal):
`make -C rust gates` exit **0**, 02:19:42Z to 02:28:24Z. Inside it,
`gate=go-suite result=PASS detail="60 package(s) run of which 45 carry a test
file, 1 excluded by name with a reason that was RUN and still fails, 5 test
file(s) not compiled by this run"` — the census moved from
`packages=61 run=59 excluded=2 with_tests=44` to
`packages=61 run=60 excluded=1 with_tests=45`, with
`ok github.com/michaellady/verified-java-websocket-port/internal/portplan 21.298s`
in the run set and NO `EXCLUSION_NO_LONGER_FAILS` and no `STALE_EXCLUSION`
finding. `ac1-gates verdict=PASS gates_passed=8/8`, ledger-gates ok,
`go test ./cmd/gosuitectl/` ok.

**Run 2, the tree that ships**, adds three comment-only corrections found by
re-reading my own change: `describeOracleMismatch`'s doc comment (it claimed the
check above was a whole-file byte compare "including a single host-provenance
line", which my change made false), the `run=59 excluded=2`/`with_tests=44`
census sentence in `cmd/gosuitectl/main.go` (now stated as measured on
2026-09-04, with the B2/B3 figures left as the history they are), and one
sentence of this record. No executable line differs between run 1 and run 2.

Run 2, commit `a7edbd4`: `make -C rust gates` exit **0**, 02:31:00Z to
02:39:30Z, `gate=go-suite packages=61 run=60 excluded=1 with_tests=45
no_test_files=15 unbuilt_test_files=5`, `gate=go-suite result=PASS`,
`ok ... internal/portplan 15.176s`, `ac1-gates verdict=PASS gates_passed=8/8`,
ledger-gates ok, and ZERO `FAIL` lines in the whole 1800-line log.
