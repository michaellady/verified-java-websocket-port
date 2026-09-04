# Two owner rulings carried out: a derived held-proposal population, and a package renamed off a criterion it does not implement

phase: ruled-implementations   step: n/a   date: 2026-09-04

STATUS: COMPLETE for what it claims, and the claims are narrow. Every exit code
below was read from the process that produced it. Both refusals were fired
against the LIVE gate, not only in a test binary, and the text each printed is
quoted verbatim. Where something was left undone it is named as left undone.

Branch `claude/ruled-implementations`, worktree isolated from the checkout that
holds `.quarantine/`. No ledger record appended, no disposition changed, no
denominator re-baselined, no owner gate triggered.

## Ruling one — `OA-held-draft-legacy-13`, node `T-held-draft-population`

> DERIVE the population from the directory rather than the hardcoded list of
> seven, and carry legacy-13-bare-lf-server-basis-correction.json as a DECLARED
> EXEMPTION with a staleness check, in the shape this repository already uses
> four times. Do NOT append to the ledger to make it green. The exemption must
> fail the moment it stops being needed.

### The premises, re-measured before anything was built on them

`internal/deltaledger.VerifyProposalDraftsAreLedgered` is rigorous about every
draft it reads. Its weakness was never the check; it was the POPULATION. The
directory holds eleven `.json` files and the list named seven, so four were
handed to nothing.

Each premise was re-derived here rather than inherited from the owner action.
Running the rule's own `ReadProposalDraft` over the four unlisted files:

```
legacy-13-bare-lf-server-basis-correction.json
  -> declared=delta-3905e4669f52383df8aa4bc2965d64f320f6e2f4fdb6b609904dba627112a906
     rebuilt =delta-3905e4669f52383df8aa4bc2965d64f320f6e2f4fdb6b609904dba627112a906
     equal=true
     subject=semantic:org.java-websocket.draft6455.server-handshake.bare-lf.hs0034.corrected:provisional-v1
div05-close-overtakes-echo-description-correction.json -> READER ERROR: ...
  carries neither a digest_preimages block nor a proposed_definition block
div06-handshake-response.json -> READER ERROR: ... carries neither ...
java-formal-binding-corroborations.json -> READER ERROR: ... carries neither ...
```

And the committed chain, recomputed from the ledger document: fifty-nine
records, fifty-nine distinct identities, and the identity legacy-13 declares is
carried by none of them. So the finding the ruling is about is real: a record
proposal whose identity is a FUNCTION of the evidence it carries, absent from
the chain, invisible to the rule that exists to refuse exactly that.

### Before

```go
// ProposalDraftPaths are the committed drafts appended at this landing. They
// are listed rather than globbed: drafts/ledger-proposals/ also holds
// java-formal-binding-corroborations.json, which is a corroboration receipt and
// not a record proposal, and a glob would silently demand a record for it.
func ProposalDraftPaths() []string {
	return []string{
		"drafts/ledger-proposals/server-close-parity.json",
		"drafts/ledger-proposals/divergence-sweep-1.json",
		...
	}
}
```

The comment is the giveaway, read three months later: it explains why one
unlisted file is not a record proposal, and says nothing about the other three
because nobody had looked. A list is a third party's word about a directory, and
a directory outlives it.

### After

The population is derived by TWO signals taken as a UNION: the STRUCTURE of a
record proposal (a `proposed_record.delta.delta_id`) or the file's own DECLARED
KIND. Leaving the population therefore takes gutting both — and a gutted file
matches no declared non-proposal kind either, so it fails as unclassified rather
than disappearing. The three genuine non-proposals leave by NAMING what they are
instead, and the kind each declares is reproduced in the census with the reason
it is out.

The gate prints the whole derivation where the result is read:

```
ok: held-draft population DERIVED from drafts/ledger-proposals/ (files=11 record_proposals=8 not_record_proposals=3 declared_exemptions=1)
     held-draft not_a_record_proposal=drafts/ledger-proposals/div05-close-overtakes-echo-description-correction.json why="ledger-record-description-correction: proposes a correction to the DESCRIPTION of a record already in the chain, not a new record; it has no delta of its own to be ledgered"
     held-draft not_a_record_proposal=drafts/ledger-proposals/div06-handshake-response.json why="divergence-closure-record: records the closure of a sweep class and asks for a pending draft to be WITHDRAWN; it proposes no record"
     held-draft not_a_record_proposal=drafts/ledger-proposals/java-formal-binding-corroborations.json why="CORROBORATION_ONLY_NO_NEW_RECORDS: a corroboration receipt whose own ledger_write_policy says it writes no records, so demanding one for it would be demanding a record it declines to propose"
     held-draft exempted=drafts/ledger-proposals/legacy-13-bare-lf-server-basis-correction.json delta_id=delta-3905e4669f52383df8aa4bc2965d64f320f6e2f4fdb6b609904dba627112a906 owner="OA-held-draft-legacy-13, RULED 2026-09-04: ..."
```

`files=11` is the whole point: the derivation sees every `.json` in the
directory, and the count is a recount of the directory rather than a number
typed here. The suite asserts that equality against a fresh `os.ReadDir` rather
than against a literal, because a hardcoded eleven is the same defect one size
larger.

### The exemption, and the three ways it is re-checked

It excuses ONE half of ONE check — the demand that the committed chain carry the
identity. The draft is still read, still rebuilt from its own six preimages, and
its declared `delta_id` must still equal that recomputation. An exemption that
also waived the recomputation would excuse the draft from being evidence at all.

It is pinned to the identity, in the shape `cmd/pinconsumerctl` uses for
`allowedPin`, so the draft cannot be edited under its own exemption. It fails as
`STALE_EXEMPTION` when the chain DOES carry the identity, when the derivation
stops classifying the path as a record proposal, and when the pin no longer
matches.

### Proof that it fires — direction one: remove the exemption

The exemption table emptied, everything else untouched, live gate:

```
$ go run ./cmd/deltaledgerctl --root . --check
deltaledgerctl: ledger integrity:
[proposal-drafts-ledgered] held ledger-proposal drafts (1 problem(s), 8 record proposal(s) derived from drafts/ledger-proposals/ of 11 file(s), 0 declared exemption(s)):
  drafts/ledger-proposals/legacy-13-bare-lf-server-basis-correction.json proposes delta-3905e4669f52383df8aa4bc2965d64f320f6e2f4fdb6b609904dba627112a906 (subject semantic:org.java-websocket.draft6455.server-handshake.bare-lf.hs0034.corrected:provisional-v1), which no record in the committed chain carries. The draft was held because the disposition vocabulary could not express it; with the vocabulary in place it must be appended, not left held
exit status 1
```

Exit 1. This is the half that proves the DERIVATION reaches the file: without the
exemption the gate is red on the committed tree, which is exactly what the owner
action predicted and exactly why appending was not the remedy.

### Proof that it fires — direction two: point it at something that no longer needs excusing

The exemption re-pointed at `server-close-parity.json`, a draft that IS in the
chain, with that draft's real identity — the shape a real stale entry takes when
the owner appends the record and nobody deletes the acknowledgement:

```
$ go run ./cmd/deltaledgerctl --root . --check
deltaledgerctl: ledger integrity:
[proposal-drafts-ledgered] held ledger-proposal drafts (2 problem(s), 8 record proposal(s) derived from drafts/ledger-proposals/ of 11 file(s), 1 declared exemption(s)):
  STALE_EXEMPTION drafts/ledger-proposals/server-close-parity.json: the exemption excuses this draft for having no record in the committed chain, and record delta-516914f1e75aaf2c86bd082772a98b204ee217f86b54cecca648826688e40b82 carries it. The acknowledgement outlived the finding and must be deleted
  drafts/ledger-proposals/legacy-13-bare-lf-server-basis-correction.json proposes delta-3905e4669f52383df8aa4bc2965d64f320f6e2f4fdb6b609904dba627112a906 ... which no record in the committed chain carries ...
exit status 1
```

Exit 1, and the refusal is by NAME rather than merely by exit code.

### Proof that it fires — direction three: edit the draft under its own exemption

The pinned identity perturbed by one character, everything else untouched:

```
$ go run ./cmd/deltaledgerctl --root . --check
[proposal-drafts-ledgered] held ledger-proposal drafts (2 problem(s), ...):
  STALE_EXEMPTION drafts/ledger-proposals/legacy-13-bare-lf-server-basis-correction.json: the exemption pins delta_id delta-...907 and the draft now declares delta-...906. The draft was edited under its own exemption, which is the one thing a pinned acknowledgement exists to catch
```

Exit 1.

### Restored

The pristine file was kept beside the worktree and restored by copy; `diff`
against it reports no difference, and the live gate returns:

```
$ go run ./cmd/deltaledgerctl --root . --check ; echo EXIT=$?
...
EXIT=0
```

### The permanent suite

`TestTheHeldDraftPopulationIsDerivedAndItsExemptionIsRECHECKED` fires all three
staleness arms plus five more against the same exported function the gate runs:
that removing the exemption fails the draft it excuses, that an exemption naming
a path the derivation cannot see is stale, that an exemption whose subject was
rewritten into a declared non-proposal is stale, that the exemption does NOT
excuse the identity recomputation, that a file declaring no classifiable kind
fails, and that an empty derivation is not a pass. Each asserts the refusal TEXT
and not merely a nonzero result. Every existing subtest in that file still
passes unchanged.

### Its ceiling, stated

- The exemption's `owner` string is prose no program can verify. Declaring a
  plausible-sounding exemption is a bypass this design makes VISIBLE in review
  and cannot close. That is the same ceiling `cmd/taskgraphctl` states for its
  `retired` entries.
- `declaredNonProposalKinds` is a vocabulary read off this corpus. A future
  draft with a genuinely new kind fails as unclassified until someone adds it,
  which is the intended direction to err in, but it is a maintenance obligation
  and not a free win.
- The derivation reads the top level of the directory only. A record proposal
  filed in a subdirectory would not be seen. `tooling/` holds one generator
  script and no `.json`.

## Ruling two — `OA-F019-master-us020-ac5`, node `T-f019-ac5-vocabulary-and-mechanism`

> The CHILD's reading governs. docs/prd-pack/01-structure-and-index.md:121
> records this repository as the Claude-runtime sibling at 9/27, not the
> canonical child at 27/27, so master US-020 AC5's blocking half is not breached
> here. Close F019 narrowed, and RENAME internal/ac5class so it stops being
> named for a criterion it does not implement.

### The load-bearing fact, verified at its line

The ruling rests on one sentence that came from a sweep. It was re-read at the
cited line before anything was built on it:

```
$ awk 'NR==121' docs/prd-pack/01-structure-and-index.md
Location: the verified-java-websocket-port project folder next to the parent ...
A sibling verified-java-websocket-port-claude (branch
claude/feature/verified-java-websocket-port, updated 2026-08-25) has the same 27
stories with 9 marked done; it is the Claude-runtime variant and is not the
canonical child.
```

Line one hundred and twenty-one, exactly as cited, saying exactly what the
ruling says it says. Corroborated verbatim a second time at
`docs/prd-pack/07a-child-prd-header-index-us001-008.md:16`. The identification of
this repository as that sibling was already established in F019 on three
independent grounds; the branch name was re-checked here and is
`claude/feature/verified-java-websocket-port`.

### Before

```go
// Package ac5class makes the US-020 AC5 defect-class list CHECKABLE rather
// than asserted.
...
package ac5class
```

### After

```go
// Package defectclass makes the CHILD PRD's seeded defect-class list CHECKABLE
// rather than asserted.
//
// IT WAS CALLED ac5class UNTIL 2026-09-04, AND THE NAME WAS THE DEFECT. Two
// documents in this corpus number their stories the same way, so "US-020 AC5"
// names two different clauses:
...
package defectclass
```

The header now names both clauses of that number, cites each by DOCUMENT, says
which one this package implements, and says in as many words that it does not
implement the other and does not claim to.

### What the rename moved, measured

`go list ./...` reports the same package total before and after — sixty-four
either way. The census diff is one name:

```
$ diff packages-before.txt packages-after.txt
43d42
< github.com/michaellady/verified-java-websocket-port/internal/ac5class
48a48
> github.com/michaellady/verified-java-websocket-port/internal/defectclass
```

So the `go-suite` package denominator does NOT move: nothing was added and
nothing removed. The gates run below reports `go-suite`'s own numbers before and
after so the claim rests on that gate's output rather than on this one.

Afterwards: `go build ./...` clean, `go test ./internal/defectclass/`,
`go test ./cmd/mutctl/` and `go test ./internal/normcollide/` all ok, and
`go run ./cmd/ac5ctl verify -root .` exits 0 with seven classes parsed from the
child PRD part and every seeded site resolved.

### The master's reading was NOT adopted, and what that leaves standing

F019 asked the owner which of two readings of the ledger's `unresolved`
dispositions binds. Neither was chosen: the ruling declines the premise, because
the master clause's blocking half governs the CANONICAL child's completion
declaration and this plane has made no such declaration. Recorded plainly, in
F019's own addendum and here:

- The blocking half still has NO mechanism. If this plane ever declares
  completion, nothing in the tree fires. Not breached is not implemented.
- The two in-tree definitions of `unresolved` still contradict each other and
  neither comment was edited.
- Sequence 53 remains the one live delta citing no owner decision.
- The count the ledger publishes is untouched.

F019 is closed NARROWED by an ADDENDUM appended beneath its original text. No
line of the original claim, its self-correction, or its three questions was
rewritten. The addendum quotes the ruling, records the re-verification, and says
which parts are not closed.

### References to the old name that were deliberately left

Two of them are in the tree on purpose, and each has a stated remedy:

- `internal/normcollide/probes.go:433` carries the old package path inside a
  `Why:` FIELD VALUE rather than a comment.
  `evidence/normalization-collisions/audit.json` reproduces that string
  byte-for-byte and is re-derived only by `normcollidectl ... write`, which needs
  the oracle harness. Changing the string without re-deriving the document would
  leave a byte comparison that fails for whoever next runs it, so the string was
  reverted and the remedy — one harness run — is named instead of performed.
  `internal/normcollide/surface.go`, whose mention is an ordinary comment, WAS
  updated.
- `evidence/ac5-class-completeness/java-arm-parity.json` names it in the
  `purpose` prose of a dated measurement record of a pinned-JVM run. This
  repository supersedes records rather than editing them.

Dated self-review records and findings that name the old package are also left
as written, for the same reason. `cmd/ac5ctl` keeps its name: it reads the child
part and implements the child's clause, so it carries the same ambiguity, but
the ruling named one package and renaming a command moves gate invocations and
evidence prose with it. Recorded as a residual rather than fixed.

## What was not done

- No ledger record was appended, and the exemption exists precisely so that
  appending stays an owner decision.
- No mechanism was built for master US-020 AC5's blocking half. The ruling did
  not ask for one and this record does not claim one exists.
- No owner gate was triggered: no AWS run, no benchmark, no Autobahn re-run, no
  `internal/lab` execution, and no label was added to any pull request.
- `origin/codex/race-catchup` was not touched.
