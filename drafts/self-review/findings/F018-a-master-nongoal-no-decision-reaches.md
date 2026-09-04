# F018 — the master PRD forbids the port's whole stance, in a line nothing in this repository has ever read

phase: master-story and PRD-metadata sweep   step: n/a   date: 2026-09-04T00:00Z

## The criterion

`docs/prd-pack/06a-prd-metadata-goal-through-sandbox.md:91`, the fourth bullet
of the master PRD's `nonGoals`:

> Do not preserve undocumented Java quirks when a declared standard or neutral
> suite has higher oracle priority

This is the master-plane statement of the anti-Java-fidelity rule. Child US-002
AC5 says a narrower version of it (*"Java is never treated as normative when it
conflicts with RFC 6455"*), and the prior story-criterion sweep declined to file
that one on the ground that US-002's subject is the oracle custodian and its
first half is about the ledger. **A `nonGoals` bullet has no such scoping
escape.** It is not a criterion of one story; it is a constraint on the program.

## What the port does, measured by the repository's own gate

`go run ./cmd/oraclerankctl --root .` regenerates
`evidence/oracle-hierarchy/adjudication-register.json` and prints:

```
oraclerankctl: wrote evidence/oracle-hierarchy/adjudication-register.json
  (92469 bytes); 640 propositions, 589 Java/Rust agreements,
  39 overridden by a higher oracle
```

`git status --porcelain` after that run is **empty** — the regeneration is
byte-identical to the committed register, so this is a recomputation of shipped
evidence and not a new artifact. Its `accounting` block:

```json
"propositions": 640, "concordant": 599, "higher_oracle_overrides": 41,
"java_rust_consensus": 589, "java_rust_consensus_overridden": 39
```

The 39, split by which oracle overrides and on what:

| governing oracle | Java+Rust agree | governing verdict | count |
|---|---|---|---:|
| rank2 in-scope Autobahn — **a neutral suite** | NON-STRICT | OK | 20 |
| rank1 RFC 6455 — **a declared standard** | open | closed | 18 |
| rank3 independent neutral expectation | closing | closed | 1 |

The nonGoal's trigger is *"when a declared standard or neutral suite has higher
oracle priority"*. The register's rank ordering is child US-020 AC2's, made
executable in `internal/oraclerank/rank.go:29-42`: RFC 6455 is rank one,
in-scope Autobahn rank two, neutral expectations rank three, **Java observation
rank four**. So on all 39, an oracle the project itself ranks above Java says one
thing, Java and the port agree on another, and the port kept Java's answer.

**39 is the count of the trigger condition firing, produced by a gate this
repository runs — not an argument.**

## That the quirks are undocumented, in the ledger's own hashed words

Recomputed over `evidence/java/behavior-delta-ledger.json`: 59 records, 52
`unresolved`, 3 `adopt-java`, 3 `fix-in-port`, 1 `intentional-correction`. **26**
rationales assert an RFC requirement.

**A correction to my own count, recorded rather than replaced.** I first wrote
31, from a regex loose enough to match the bare substring `violat`. Tightening
it gives 26 — and 26 is still not the number that supports this finding, because
**seven of those records run the OTHER way**: sequences 36, 37, 38 (the
client-side handshake budgets) and 45, 46, 47 (the server-side budget
corrections that supersede 14, 15, 16) are all
`SAFE STRENGTHENING, NOT A LENIENCY DIVERGENCE` — the port keeps a handshake
budget shipped Java has none of — and sequence 19
says ws_core *"deliberately does NOT emulate the untested negative-length
path"*. Those are the port being **stricter** than Java, which is outside this
class by direction — and it is precisely the error
`drafts/self-review/story-criterion-sweep.md` §5 records against itself, having
classified sequences 14-16 and 45-47 from their subject lines and found on
reading them that they were the reverse. I made the same mistake with a regex
instead of a subject line.

Dropping the seven and one superseded record leaves **18 live records where the
RFC requires something and the port follows Java instead**: sequences 1, 2, 3, 4,
5, 6, 8, 17, 18, 23, 25, 29, 39, 42, 44, 48, 50, 53. **The 39 overrides above are
unaffected** — they come from the adjudication register, computed from corpus and
Autobahn evidence, not from this count. Six of the 18, verbatim, each a preimage
hashed into its record's digest:

- seq 1 — *"the RFC requires a Host header; the live pinned Java server accepted
  the request with no Host header (**never examined**)"*
- seq 6 — *"the RFC requires a base64 16-byte key; the live pinned Java server
  accepted a non-base64 key and derived the accept from the raw string"*
- seq 17 — *"the RFC requires rejecting non-minimal length encodings with 1002;
  the pinned Java runtime **performs no minimality check** and accepts both
  forms"*
- seq 18 — *"the RFC requires rejecting role-inappropriate masking with 1002;
  the pinned Java runtime accepts either masking toward either role"*
- seq 25 — *"the RFC requires a pong response to every ping; the pinned
  runtime's oracle-observable core never auto-pongs"*
- seq 48 — the class record: *"EIGHTEEN scenarios across ten families, all
  caused by the oracle adapter never routing through
  WebSocketImpl.decodeFrames"*

"Never examined." "Performs no minimality check." These are accidents of the
Java implementation, not documented behaviours of it. That is what an
*undocumented quirk* is.

## The clause has never been read by anything in this repository

```
grep -rn "undocumented Java quirks" .   →  1 hit: the PRD line itself
grep -rn "higher oracle priority"   .   →  1 hit: the same line
```

Exactly one Go PACKAGE in the tree cites a master story at all —
`internal/mutdenom`, at `model.go:403` and `check.go:499`, both about US-002's
dual-blind rule. (I first wrote "one Go file" from a filename-only grep;
widening it to the phrase `master (prd|story|us-0)` returns two files in that
same package and nothing else.) Every other PRD citation in Go points at
`docs/prd-pack/07c-child-prd-us020-us027.md`, the child.
No gate, no ledger rationale, no self-review record, and no owner decision names
this line.

## Why no standing decision reaches it — checked first, not last

F010's addendum 3 records that four passes over one question never grepped the
decisions directory. That check was run here **before** this was called a
finding, with `VJWP_PROTECTED_STORE=$PWD/evidence/governance/decisions` exported:

```
grep -rli "nongoal|oracle priority|oracle-priority|prd-pack|oracle hierarchy" \
  evidence/governance/decisions/          →  exit 1, no matches
grep -rli "master" evidence/governance/decisions/
                                          →  company-move-record.json only
```

**Not one of the 63 JSON records in the store names the master PRD, its nonGoals, its
metadata, or any master story.** The two instruments that clear the equivalent
child clauses both stop short:

- **`us010-016-ac-amendment-owner-decision-2026-08-27.json`** (sha256
  `26849b5ea74006504d18507ac694c00e882e7fd37d4cd8c8502ea824e96ea974`, recomputed)
  amends *"every AC clause of US-010..US-016"*. A `nonGoals` bullet is not an AC
  clause; and its `context` names *"mask/noncanonical-length rejection, RFC
  close-code table + echo matching, RFC handshake validation gate, automatic-pong
  policy, control payload caps"* — all **child** subjects, while the **master's**
  US-010..US-016 are CommonMark, JSON Schema and publication stories.
  `docs/prd-pack/README.md` warns about exactly this collision in its own voice.
- **`us009-us008-owner-decisions-2026-08-27.json`** key `us009_normativity`,
  choice `JAVA_FAITHFUL_PLUS_SAFE`, is plane-wide — but its own `plane` field
  reads `"verified-java-websocket-port-claude (Claude authority plane)"`. It is a
  child-plane record.

## The two readings, and the fact that bears on them

**Generous reading — the clause does not bite.** *Undocumented* means
undocumented anywhere; all 39 are documented in the Behavior Delta Ledger with
hashed rationales; and `JAVA_FAITHFUL_PLUS_SAFE` is the owner's own later
statement of stance, so it governs every behavioural question the port asks
regardless of which document raises it.

**Narrow reading — the clause bites on all 39.** *Undocumented* describes the
quirk as it exists in **Java**, and the port's ledger cannot retroactively make
Java's accident documented; the ledger documents the port's *adoption*, which is
a different thing. And a decision whose own `plane` field names the child plane
does not amend a document belonging to the parent program.

**There is also a reading of the clause's own structure that favours the narrow
one, and I record it because it cuts against the comfortable answer.** If
*undocumented* meant *unledgered*, the second half — *"when a declared standard
or neutral suite has higher oracle priority"* — would do no work, because an
unledgered divergence is already forbidden twice over: by `architectureNotes`
(*"every Java/Rust/spec disagreement enters the Behavior Delta Ledger"*) and by
master US-020 AC5. A reading that leaves the oracle-priority condition inert is
the weaker reading.

**And one dated fact bears on the plane question.** The two child-plane decisions
were made **2026-08-27**. `docs/prd-pack/01-structure-and-index.md:5` records the
master `prd.json` as *last updated `2026-08-29T12:22:36Z`*, with the pack
snapshotted 2026-09-01. So the master PRD was edited **two days after** both
decisions and still carries this nonGoal. That is not proof the owner considered
and kept it — an HQ edit elsewhere in the file would produce the same timestamp —
but it is the only evidence either way, and it points away from the generous
reading rather than toward it.

## What this is NOT, stated so nobody inflates it

- **Not a claim that the port should change.** Under either answer the 39
  behaviours stay: they are what `JAVA_FAITHFUL_PLUS_SAFE` and the AC amendment
  produced, and the prior sweep priced removing them.
- **Not a re-filing of the register's own BLOCKING finding.** The register
  already carries `ORACLE-RANK-AC2-OVERRIDES` and asks the owner to *"adjudicate
  each enrolled proposition"* against **child** US-020 AC2. This finding is about
  a **different document** that nothing in the tree cites, and the child-level
  adjudication would not answer it.
- **Not evidence that the 39 are wrong.** Twenty of them are Autobahn NON-STRICT
  rows, and `us019-owner-decisions-2026-08-28-d.json` id
  `us019-ac3-strict-pass-reading` already ruled that the port need not beat
  shipped Java there — *"Meeting it literally would require the port to behave
  BETTER than shipped Java on 11 cases, contradicting the JAVA_FAITHFUL_PLUS_SAFE
  normativity decision."* That ruling amends **child US-019 AC3**. It does not
  name the master nonGoal, which is the whole asymmetry this finding is about.
- **rank1's binding is weak and the register says so.** `ORACLE-RANK-BINDING-1`
  discloses that `rank1-rfc6455` is `CONTENT_BOUND_TO_RECORDED_READING`, and *"a
  misreading would pass this gate unchanged."* The 18 rank-one rows inherit that
  weakness. The 20 rank-two Autobahn rows do not: they are read from executed run
  artifacts.

## Bin

F010's class with the scope moved one level up. F010 was *fidelity standing in
for correctness* — a change verified against the source it imitates and never
against the specification governing whether imitation is wanted. This is the same
failure with a second turn on it: **the specification that governs was found, was
read, and was amended — in the child document — while an identically-worded
constraint sat in the parent document that no gate, no decision and no review in
this repository has ever cited.** Four passes over F010 missed a decision because
nobody grepped the decisions directory. This one was missed because everybody
grepped `07{a,b,c}`.

The portable rule: when an amendment clears a criterion, check whether the same
constraint is stated anywhere the amendment does not reach. A criterion is a
sentence, not a location, and the same sentence in two documents needs two
rulings.

## Owner decision required

**One question.** Does the master PRD's `nonGoals` bullet reach the 39
propositions this repository's own register enrols — and if not, is that because
of what *undocumented* modifies, or because a child-plane decision may amend a
master-plane nonGoal? Either answer is small to write and neither moves a byte of
the port. What it settles is whether the port's stance is **compliant** with the
master PRD or merely **tolerated** by it, and today the record says neither.

## Status

Filed. No port source changed, no ledger record edited, no denominator
re-baselined. `cmd/oraclerankctl` was run and its output verified byte-identical
to the committed register. Full corpus derivation, the robustness table this
finding came out of, and the sweep's ceiling:
`drafts/self-review/master-story-sweep.md`.
