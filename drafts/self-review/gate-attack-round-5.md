# Adversarial round 5 — VerifyAdjudication and VerifyCommittedCorporaReDerive, the two ledger rules round 4 read and did not attack

STATUS: COMPLETE for what it claims, and narrow on purpose. Every exit code
below was read from the process that produced it, never from a log line saying
PASS, and never from the exit status of a `tail` at the end of a pipe — one
reading in this round was thrown away for exactly that reason and re-taken.
Where an attack was caught by a SIBLING rule rather than by the one I was
attacking, I name the sibling.

Base: `claude/feature/verified-java-websocket-port` at `428dd5a`, worked in an
isolated worktree `/home/user/vjwp-attack5` on branch
`claude/gate-attack-round-5`, with `.quarantine` symlinked in and never staged.

Scope is round 4's own section 4, verbatim and nothing else:

> **`VerifyAdjudication` and `VerifyCommittedCorporaReDerive`**: READ, NOT
> ATTACKED. Two of the eight ledger rules in my brief. I ran out of round after
> 2a turned into a live defect that needed proving by execution. Reporting them
> as survivors would be the exact lie this task was created to correct.

The organising question is the one four rounds have converged on:

> Does the check RE-DERIVE its claim, or does it verify that a DECLARATION is
> well formed?

**Two attacks got a bad tree past `ledger-gates` at exit 0, one per rule** — one
of them by mutating production code, a class round 4 declined and section 1c
argues about in the open. Both
are fixed here, each with the attack refused and the unmodified tree still
green. Both left every published counter identical, which is the round-4
prediction holding for a fifth time: the dangerous bypass moves no number.

**No denominator moved.** No corpus size, no census total, no published residual
changes value in this round. `OA-oracle-census-anchor` is untouched and stays
open. No new owner action is raised, because neither fix needed one.

## Scoreboard

| # | rule | attack | before | after |
|---|---|---|---|---|
| A1 | VerifyAdjudication | ledger sequence 59 declares `rfc-governs` while its own hashed rationale says the divergence is RETAINED | exit 0, counters identical | exit 1 |
| A2 | VerifyAdjudication | raise `PreVocabularySequence` past the sealed set | exit 1 | held (sibling: legacy-record-adjudications) |
| A3 | VerifyAdjudication | break the residual counter AND regenerate, so the published number and its check are the same function over the same records | exit 0, chain head byte-identical | exit 1 |
| A4 | VerifyAdjudication | add a term to the Go disposition vocabulary and use it | exit 1 | held (sibling: evidence-document-schemas) |
| C1 | VerifyCommittedCorporaReDerive | edit the seed alone | exit 1 | held (the rule's own polarity) |
| C2 | VerifyCommittedCorporaReDerive | swap the seed AND regenerate both corpora | exit 1 | held (sibling: the ledger-equals-regeneration comparison) |
| C3 | VerifyCommittedCorporaReDerive | the public manifest declares a false length for the corpus it seeds | exit 0 | exit 1 |
| C4 | VerifyCommittedCorporaReDerive | the handshake manifest declares an all-zero digest and a false length | exit 0 | exit 1 |
| C5 | VerifyCommittedCorporaReDerive | the handshake manifest names a seed its corpus was never derived from | exit 0 | exit 1 |

C3, C4 and C5 also passed the whole `internal/corpora` test package, so
`go-suite` did not catch them either. The public manifest's DIGEST alone was
reconciled in `internal/corpora/committed_test.go`, which is go-suite's to run
and was never this gate's.

---

## 1. VerifyAdjudication — what it checks and over what

`internal/deltaledger/adjudication.go`. `VerifyIntegrity` calls it as

    VerifyAdjudication(committed.Records, committed.RecordsWithoutMismatchClass)

**The population is the whole committed chain**, and it is derived rather than
listed — which is the first thing round 4's section 2a made me check. The chain
comes from `evidence/java/behavior-delta-ledger.json`, and by the time
`VerifyIntegrity` runs, `cmd/deltaledgerctl --check` has already refused any
document that is not byte-equal to the regeneration from `Definitions()`. Each
record's `sequence` is assigned by `lab.AppendBehaviorDelta` from its position
in the chain, never written beside a definition, so the boundary rule 2 tests
cannot be moved by editing a field. The rule is total over that population: it
loops every record and every record must satisfy every arm.

The arms, as the code has them:

1. VOCABULARY — disposition and any non-empty mismatch class are in
   `lab.Dispositions()` and `lab.MismatchClasses()`.
2. NO NEW RECORD IS UNCLASSED — a record after `PreVocabularySequence` carries a
   class.
3. AN ADJUDICATED RECORD IS CLASSED — a disposition other than `unresolved`
   requires a class.
4. AN UNCLASSED RECORD MUST HAVE SAID SO IN ITS OWN BYTES — no class requires a
   retention statement inside the hashed rationale.
5. NO CONTRADICTION — a record asserting retention must not declare a
   disposition that contradicts it.
6. (added by this round) the converse of 2.

Plus the published residual.

### 1a. Rule 5's contradiction set was missing the one term the retention sentence names (A1)

`AssertsRetention` matches either of two sentences carried verbatim inside a
record's hashed rationale. The first of them reads, in part:

> the divergence is deliberately retained under JAVA_FAITHFUL_PLUS_SAFE, not
> resolved toward the RFC.

Rule 5 refused `fix-in-port` and `intentional-correction` against that sentence.
It did not refuse `rfc-governs`, whose meaning in `internal/lab/ledger.go` is
"the RFC's requirement governs and the port follows the RFC rather than Java" —
the one disposition the sentence rules out BY NAME.

At the rule level, the same record, the same prose, two dispositions:

```
=== A: seq59 rfc-governs + retention statement ===
VerifyAdjudication: nil (ACCEPTED) seq=59 disposition="rfc-governs" dropClass=false published=49

=== B: control, seq59 fix-in-port + retention statement ===
VerifyAdjudication: REFUSED
adjudication (1 problem(s)):
  sequence 59 declares disposition "fix-in-port" while its hashed rationale states the divergence is deliberately RETAINED. The field and the prose contradict each other, and the prose is inside the digest preimage
```

That is a rule-level probe, so I made it reach the gate. Ledger sequence 59 is
the last record in the chain and its definition is
`internal/deltaledger/definitions_ac2_ruling.go`. I set its `Disposition` to
`rfc-governs` and appended the shorter retention sentence to its rationale
(the shared `ownerDecision` citation, which carries the longer one verbatim,
overruns the 4096-byte rationale bound on this particular record and was
refused by `lab.BehaviorDelta.Validate` — a NON-RESULT, not a survivor, and the
reason the injected sentence is the short one). Then `deltaledgerctl --root .`
to regenerate, and `--check`:

```
ok: evidence/java/behavior-delta-ledger.json equals the regeneration (59 records, head sha256:9d41cbac269ef20f8d003e437e4c8d4c6b9aae0581e8aeb03adc97ea418f4840, document schema 1.2.0)
ok: ledger integrity verified (frozen prefix through sequence 35, ledger envelope, evidence document schemas, observation provenance, handshake mapping census, protocol-rejection class, census evidence and ledger binding, supersessions, adjudication, held proposal drafts, legacy-record adjudications, unledgered_disagreements recomputed = 0, records_without_mismatch_class recomputed = 49)
EXIT=0
```

Every counter is the baseline's. The head digest differs because the record's
own bytes differ, which is the chain working; nothing about the census moved.
The control, the same tree with `fix-in-port` in place of `rfc-governs`:

```
deltaledgerctl: ledger integrity:
[adjudication] adjudication (1 problem(s)):
  sequence 59 declares disposition "fix-in-port" while its hashed rationale states the divergence is deliberately RETAINED. The field and the prose contradict each other, and the prose is inside the digest preimage
exit status 1
EXIT=1
```

So rule 5 was live and only its set was short. **This matters beyond the
demonstration**: the shared `ownerDecision` citation, appended to about
twenty-four definition sites in this package, CONTAINS the long retention sentence,
so any future record that cites the owner decision the ordinary way carries a
retention assertion whether its author meant one or not — and could have
declared `rfc-governs` beside it with nothing objecting.

### 1b. The published residual and its check are the same function (A3)

Stated carefully, because my first summary of this overstated it and a reader
who checks an overstatement against the source discounts everything around it.

The rule ended with

    residual := CountRecordsWithoutMismatchClass(records)
    if residual != publishedResidual { ... }

and its doc comment claimed it "recomputes the published residual and refuses a
document that understates it".

**That comparison is not dead, and I checked both readings by execution rather
than by argument.** I hand-edited the committed document's integer from 49 to 7
and ran the two entry points.

`VerifyIntegrity` called on its own over that document REFUSES it, naming this
very recount:

```
VerifyIntegrity: REFUSED
[adjudication] adjudication (2 problem(s)):
  the ledger publishes records_without_mismatch_class=7 but 49 of the 59 records carry no class
```

Inside `cmd/deltaledgerctl --check`, which is what `ledger-gates` runs, the same
hand edit is refused one step EARLIER and never reaches the rule at all:

```
deltaledgerctl: evidence/java/behavior-delta-ledger.json does not equal the deterministic regeneration (59 records, head sha256:f10dd526fd73b4b321a16d2a439901375b8be67235be4aca61daad75b3d81195)
exit status 1
```

So a typed-in number is caught, twice over. **What neither catches is a broken
COUNTER plus a regeneration.** `BuildLedgerFileFrom` writes the residual as
`CountRecordsWithoutMismatchClass(records)` and the rule recomputed it with that
same function over those same records, so the two sides agree with each other by
construction whatever the function does. That is round 4's `built := existing`
shape one level down: not a comparison that cannot fail, but two computations
that are supposed to be independent and are identical.

Reproduced by disabling the counter's body with `false && (<the whole original
condition>)` and nothing else:

```
func CountRecordsWithoutMismatchClass(records []lab.BehaviorLedgerRecord) int {
	count := 0
	for _, record := range records {
		if false && (record.Delta.MismatchClass == "") {
			count++
		}
	}
	return count
}
```

`deltaledgerctl --root .` then wrote `records_without_mismatch_class = 0 of 59`
and `--check` said:

```
ok: evidence/java/behavior-delta-ledger.json equals the regeneration (59 records, head sha256:f10dd526fd73b4b321a16d2a439901375b8be67235be4aca61daad75b3d81195, document schema 1.2.0)
ok: ledger integrity verified (... unledgered_disagreements recomputed = 0, records_without_mismatch_class recomputed = 0)
EXIT=0
```

Note the head: **byte-identical to the baseline**. The residual lives in the
document envelope and not in any digest preimage, so the whole hash chain is
unmoved while the committed document publishes that no record in it lacks an
AC3 attribution, when forty-nine of them do. The word in that gate line which
was not true is "recomputed".

`TestTheCommittedChainIsAdjudicated` asserted the true value and the true
partition, and only in the test binary. `go-suite` runs it; `ledger-gates` did
not.

### 1c. Is A3 an attack, or a deletion attack? Round 4 drew a line and I am drawing it in a different place

Round 4 declined one probe of this shape and said so explicitly, which is why I
have to answer it rather than quietly disagree:

> **The evidence-integrity call.** I considered a deletion attack on
> `VerifyEvidenceIntegrity` — replacing the pinned-file count with a literal
> would leave the cross-check string identical and the register byte-identical —
> and did not run it, because it is a deletion attack on production code rather
> than a bad tree passing a gate, and round 3 already established that class
> three times. It is named here so it is not reported as covered.

A3 mutates production code, so by the letter of that sentence it is the declined
class. **I think round 4 was right about the instance and its stated reason is
too broad as a rule, and I am applying a narrower one.** The line I used is
whether the mutated tree leaves a COMMITTED ARTIFACT STATING SOMETHING FALSE
ABOUT ITSELF while a gate certifies it.

- Round 4's instance fails that test in its own words: the register stays
  byte-identical and the cross-check string is unchanged. Nothing in the tree
  lies afterwards; a rule is merely weaker. Declining it was correct, and
  "delete rule X and find that nothing else catches X" is a question with a
  known answer for every rule in this repository.
- A3 passes it. After the mutation `evidence/java/behavior-delta-ledger.json`
  publishes `records_without_mismatch_class: 0` about a chain in which
  forty-nine records carry no class, and `ledger-gates` prints that number back
  with the word "recomputed" in front of it. The defect being demonstrated is
  not that the rule is removable. It is that the rule's computation and the
  builder's computation are the SAME computation, which is a property of the
  code as committed today and is true whether or not anyone ever mutates
  anything. The mutation is how I made that property visible; it is not the
  finding.

I would rather have the two rounds disagree in the open than have them apply
different standards silently. If the owner holds round 4's broader line, then
A3 should be read as a HARDENING rather than as a gate defeated, and rule 6
stands on its own merits either way: it makes the published residual a
consequence of the chain's sequences instead of a second call to the function
that wrote it.

### 1d. What I attacked in VerifyAdjudication and could NOT defeat

- **A2, moving the grandfathering boundary.** `PreVocabularySequence` is the one
  constant rule 2 consults, and its own comment claims it is "a pin on the
  chain, in the same shape as `FrozenPrefixSequence`" — which it is not, since
  `FrozenPrefixSequence` has a digest constant beside it and this has nothing. I
  raised it to 50 and rebuilt. `ledger-gates` refused, at exit 1, in three
  places at once, all of them in the SIBLING rule
  `VerifyLegacyAdjudications`: the committed document's `pre_vocabulary_head` no
  longer matches the record digest at the new boundary, its declared
  `pre_vocabulary_sequence` no longer equals the constant, and the record at the
  new boundary carries no legacy adjudication entry. The boundary is anchored —
  by content, and by another file — just not where its comment says.
- **A4, drifting the closed vocabulary.** I added a term to `lab.Dispositions()`
  and gave sequence 59 that disposition. Rule 1 accepted it, and the tree was
  refused at exit 1 by `evidence-document-schemas`, on the committed JSON Schema
  whose `enum` carries the same five terms. Two independent statements of the
  vocabulary, and the gate reads both.
- **A rationale that quotes a retention sentence in order to deny it.**
  `AssertsRetention` is `strings.Contains`, so "this record does NOT say that
  <sentence>" reads as an assertion. I could not turn that into a bypass in
  either direction: for rule 4 the containment is what an attacker WANTS to be
  true, and the only records the rule excuses are sealed and cannot be edited
  without breaking the frozen prefix; for rule 5 the containment only makes the
  refusal fire more often. I record it as a known imprecision with no path to a
  bad tree, not as a finding.
- **Sequence forgery.** Rule 2's exemption is keyed on `record.Sequence`, so a
  duplicate or lowered sequence would be the way in. Sequences are assigned by
  `lab.AppendBehaviorDelta` from chain position and a definition cannot name
  one, so there is nothing to forge from the definition side, and a
  hand-edited document dies on the regeneration comparison.
- **The empty population.** `VerifyAdjudication` loops the chain and refuses
  nothing when the chain is empty: no record fails an arm, the residual is
  zero, and a document publishing zero is accepted. Several rules in this
  package fail closed on an empty artifact by name, and this one does not. I
  could not turn it into a bad tree and I say why rather than filing it: an
  empty or truncated chain is refused by `VerifyFrozenPrefix`, which
  `VerifyIntegrity` calls first over the same slice and whose findings join
  into the same error, and by `--check`'s regeneration comparison before that.
  It is a fail-open shape with two rules standing in front of it, so it is
  recorded here and not fixed.
- **Neither rule uses a regular expression**, so the anchored-pattern class the
  brief named — `^` with no `(?m)` — does not arise in either. I checked both
  files for it rather than assuming.

---

## 2. VerifyCommittedCorporaReDerive — what it checks and over what

`internal/deltaledger/evidence_census.go`. It reads
`corpora/public/manifest.json`, takes `generator.public_seed`, refuses an empty
one rather than skipping, calls `corpora.RenderCommittedCorpora(seed)`, and
requires each of two committed corpus files to be byte-identical to its half of
that derivation.

**The population is two files, written as a literal pair in the function.** That
is the shape round 4's live defect had, so I enumerated what else is tracked
under the corpus tree. Six files are tracked. Two are the corpora this rule
re-derives. Two more are the held-out tiers' manifests, whose artifacts are
declared `stored_in_repo: false` with a `protected-secret` seed visibility, so
this rule cannot re-derive them and correctly does not try. The remaining two
are the manifests OF the two corpora it does re-derive, and those are where the
round went.

`corpora.GeneratePublic` reads nothing from disk: it is a pure function of the
seed string. So the derivation half is a genuine derivation and not a copy of
its own output. That is the part of this rule that is exactly as strong as it
says.

### 2a. Polarity, first (C1)

Changing the seed in the manifest and nothing else:

```
deltaledgerctl: ledger integrity:
[committed-corpora-rederive] corpora/public/scenarios.jsonl does not re-derive from the committed seed in corpora/public/manifest.json. This corpus is an INPUT to the divergence measurement, so an edit to it moves what the gate is able to demand; the identity check used to run only in a test binary, which is not a gate
exit status 1
```

The rule fires. Any edit to either corpus file is caught byte-exactly; I did not
find a corpus edit it misses, and I do not think one exists.

### 2b. The seed is a declaration, and swapping it wholesale is caught elsewhere (C2)

The seed the corpora are re-derived FROM is read out of the same document family
the rule is verifying. `cmd/corporactl` holds the same string as
`DefaultPublicSeed` and the verifier does not consult it. So I changed the seed
and regenerated both corpus files from the new one, which this rule then
accepts by construction. The tree was refused at exit 1 anyway, by the sibling
comparison in `cmd/deltaledgerctl` that runs before `VerifyIntegrity`:

```
deltaledgerctl: evidence/java/behavior-delta-ledger.json does not equal the deterministic regeneration (59 records, head sha256:f10dd526fd73b4b321a16d2a439901375b8be67235be4aca61daad75b3d81195)
exit status 1
```

The corpus content reaches the record definitions, so a corpus swap cannot be
silent. **HELD, by a sibling, and I say so rather than crediting this rule.**

### 2c. The manifests could misdescribe the very corpora this rule re-derives (C3, C4, C5)

The rule took one field out of one manifest and asked nothing else about either
manifest. Three states were reachable, each reproduced by execution, each with
`go run ./cmd/deltaledgerctl --root . --check` at exit 0 and its census line
byte-identical to the baseline, and each ALSO green under
`go test ./internal/corpora/`:

- the public manifest declaring a length of one byte for the corpus it seeds;
- the handshake manifest declaring an all-zero digest and a length of two bytes
  for the corpus this rule re-derives byte-for-byte;
- the handshake manifest naming a `generator.public_seed` its corpus was never
  derived from, while the public manifest's — the one actually used — stayed
  correct.

The public manifest's digest was reconciled by
`internal/corpora/committed_test.go`, and that is a test binary, which is the
criticism this function's own comment makes of the state it replaced. Its
`bytes` field and the entire handshake manifest were reconciled by nothing at
all. A manifest that seeds a derivation and then misdescribes its result is a
declaration verified against a copy of itself: the artifact says what the corpus
is, and the corpus was checked while the saying was not.

---

## 3. The fixes, and both directions for each

**F1 — `contradictsRetention`** (`internal/deltaledger/adjudication.go`). Rule
5's set becomes `fix-in-port`, `intentional-correction` and `rfc-governs`, in a
named function with the reason attached. The attack, refused:

```
deltaledgerctl: ledger integrity:
[adjudication] adjudication (1 problem(s)):
  sequence 59 declares disposition "rfc-governs" while its hashed rationale states the divergence is deliberately RETAINED. The field and the prose contradict each other, and the prose is inside the digest preimage
exit status 1
EXIT=1
```

**F2 — the residual is derived from the chain's sequences** (same file). Rule 6
states the converse of rule 2 — a record at or before the boundary carries no
class — and with both directions in hand the residual is a function of the
sequences, which `lab.AppendBehaviorDelta` assigns and which the frozen prefix
and the legacy document's `pre_vocabulary_head` pin. The old recount STAYS,
because it is not dead: it is what refuses a hand-edited integer when
`VerifyIntegrity` is called on its own, as section 1b quotes. What the new
comparison adds is independence — the two sides are no longer the same function
over the same records. The attack, refused:

```
deltaledgerctl: ledger integrity:
[adjudication] adjudication (1 problem(s)):
  the ledger publishes records_without_mismatch_class=0, but 49 of the 59 records are at or before the pre-vocabulary sequence 49 and every one of those carries no class while every record after them carries one. The residual is a consequence of the chain's SEQUENCES, not a number to be counted out of the same field the builder counted and compared with itself
exit status 1
EXIT=1
```

**F3 — each corpus is reconciled against its OWN manifest**
(`internal/deltaledger/evidence_census.go`). `verifyCorpusManifestDescribes`
re-derives, for both corpora, the seed the manifest names, the artifact path it
describes, its digest and its length, all against the DERIVED bytes rather than
against the committed file, so it is a statement about what the generator
produces and not a digest of a file compared with a digest of the same file. The
five attacks, refused, one field edited per run:

```
[committed-corpora-rederive] corpora/public/manifest.json declares scenarios.jsonl at 1 bytes, but the corpus derived from the committed seed is 342167 bytes
[committed-corpora-rederive] corpora/public/manifest.json declares scenarios.jsonl at sha256:0000000000000000000000000000000000000000000000000000000000000000, but the corpus derived from the committed seed digests to sha256:fe1735bc42c11f66afe2965a7449fc6cad31cca3e2048305388241c781501e5f. The manifest is the artifact that says what the corpus IS; a manifest that seeds the derivation and then misdescribes its result was accepted by this gate until round 5
[committed-corpora-rederive] corpora/handshake/manifest.json declares cases.jsonl at sha256:0000000000000000000000000000000000000000000000000000000000000000, but the corpus derived from the committed seed digests to sha256:64d6dea5d63c6eb7d4698dccbe485f0ce249b511109df657848c511f0177e605. The manifest is the artifact that says what the corpus IS; a manifest that seeds the derivation and then misdescribes its result was accepted by this gate until round 5
[committed-corpora-rederive] corpora/handshake/manifest.json declares generator.public_seed "a-seed-this-corpus-was-never-derived-from", but corpora/handshake/cases.jsonl is derived from the seed "us005-public-calibration-seed-v1" that corpora/public/manifest.json declares. Two manifests naming two seeds for one derivation means one of them describes a corpus this repository does not hold
[committed-corpora-rederive] corpora/handshake/manifest.json declares cases.jsonl at 2 bytes, but the corpus derived from the committed seed is 26254 bytes
```

each at exit 1, and the fifth arm — a manifest that lists a second artifact this
rule does not re-derive — refused with `lists 2 artifacts`.

**The other direction, the unmodified tree with all three fixes in place:**

```
ok: evidence/java/behavior-delta-ledger.json equals the regeneration (59 records, head sha256:f10dd526fd73b4b321a16d2a439901375b8be67235be4aca61daad75b3d81195, document schema 1.2.0)
ok: evidence/java/ledger-supersessions.json equals the chain's supersession map (6 link(s), also declared in the ledger document)
ok: ledger integrity verified (frozen prefix through sequence 35, ledger envelope, evidence document schemas, observation provenance, handshake mapping census, protocol-rejection class, census evidence and ledger binding, supersessions, adjudication, held proposal drafts, legacy-record adjudications, unledgered_disagreements recomputed = 0, records_without_mismatch_class recomputed = 49)
ok: evidence/java/legacy-record-adjudications.json adjudicates records 1-49, each bound to its record by recomputed identity, record digest and a unique verbatim rationale quote (records_without_ac3_class recomputed = 0 of 59)
ok: evidence/governance/owner-decision-digests.json equals the derivation and 7 governance record digest(s) recomputed from the protected store and matched
EXIT=0
```

Byte-identical to the baseline taken before any edit, head included.

**Polarity in the test binary too.** Three subtests added to
`TestVerifyAdjudicationRefusesEachWayARecordCanSayNothing` and one table of five
in `TestACorpusManifestCannotMisdescribeTheCorpusItSeeds`, each asserting the
REFUSAL TEXT and not merely a non-nil error, so a probe that goes red for
another reason is not read as a pass. `degradedRootArtifacts` gains the
handshake manifest, because a rule that now reads it would otherwise fail every
unrelated probe for the wrong reason.

---

## 4. What I did NOT attack, and what I did not try

- **No owner gates.** No AWS run, no benchmark, no Autobahn run, no
  `internal/lab` execution path. **No label was added to any pull request.**
  `origin/codex/race-catchup` was not touched. No hidden or sealed tier was
  generated, read or run.
- **Nothing from rounds 1 to 4 was re-attacked.** The other six ledger rules
  round 4 covered, `oracle-hierarchy-gates`, `fmt-check`, `clippy`,
  `record-guard`, `pin-guard`, `plan-guard`, `go-suite`, `fixture-guard` and
  `ac1-gates` were left exactly as those rounds left them. This round is two
  rules and no more, and I finished it inside the round rather than widening.
- **`OA-held-draft-legacy-13` and `OA-oracle-census-anchor` are untouched.** The
  first is round 4's live defect and is an owner action for the reason round 4
  gives; the second covers the agreement and override counts and I bound
  neither.
- **The held-out tier manifests.** Out of this rule's reach by construction and
  left alone; extending the reconciliation to them would need the custodian
  secret, which is a tier I am forbidden to touch.
- **The corpus schemas.** `ValidateCorpusSchemas` runs in a test binary and not
  in `ledger-gates`, which is the same shape as the findings above, but it is a
  different rule from either of mine and I did not pull on it. Naming it is what
  I can honestly do with it.
- **`cmd/corporactl.DefaultPublicSeed`.** I did not bind the manifest seed to it.
  A Go constant is exactly as editable as a JSON field, so the bind would add
  ceremony rather than a derivation; the reconciliation that does bite is the
  digest one, which is in F3.

---

## 5. The chain, and the full gates run

Recorded in section 6 of this file after the run completed. Both exports were
set for every invocation in this record:

```
export VJWP_PROTECTED_STORE=$PWD/evidence/governance/decisions
export PATH=/home/user/verified-java-websocket-port/.quarantine/jdk-17.0.19+10/bin:$PATH
```

Without the first, `ledger-gates` REFUSES rather than passing, and a refusal is
not a pass. Without the second, `internal/portplan` fails `JAVAC_UNAVAILABLE`.

## 6. The gates run

`make -C rust gates`, both exports set, run from `/home/user/vjwp-attack5`
with the round's changes staged. The exit code was captured from the make
process into a file inside this worktree, never read from a log line:

```
GATES_EXIT=0
```

All twelve targets ran: `fmt-check`, `clippy`, `fixture-guard`, `record-guard`,
`pin-guard`, `plan-guard`, `go-suite`, `test`, `test-release`, `ac1-gates`,
`ledger-gates`, `oracle-hierarchy-gates`. The verdict lines each gate printed:

```
gate=fixture-liveness-guard result=PASS
gate=record-content-precondition result=PASS
gate=record-prose result=PASS
gate=pin-dangling result=PASS detail="no undeclared drift; 15 acknowledged finding(s) each naming an owner action"
gate=task-graph result=PASS detail="every done node's evidence re-derived; 0 ready, 21 blocked on 24 open owner action(s)"
gate=go-suite result=PASS detail="61 package(s) run of which 46 carry a test file, 1 excluded by name with a reason that was RUN and still fails, 5 test file(s) not compiled by this run"
gate=forbid-unsafe verdict=PASS
gate=dependency-inventory verdict=PASS
gate=msrv verdict=PASS
gate=license verdict=PASS
gate=audit verdict=PASS
gate=lockfile verdict=PASS
gate=canaries verdict=PASS
gate=adapter-linkage verdict=PASS
ac1-gates verdict=PASS gates_passed=8/8
```

`ledger-gates`, the gate this round is about:

```
ok: evidence/java/behavior-delta-ledger.json equals the regeneration (59 records, head sha256:f10dd526fd73b4b321a16d2a439901375b8be67235be4aca61daad75b3d81195, document schema 1.2.0)
ok: evidence/java/ledger-supersessions.json equals the chain's supersession map (6 link(s), also declared in the ledger document)
ok: ledger integrity verified (frozen prefix through sequence 35, ledger envelope, evidence document schemas, observation provenance, handshake mapping census, protocol-rejection class, census evidence and ledger binding, supersessions, adjudication, held proposal drafts, legacy-record adjudications, unledgered_disagreements recomputed = 0, records_without_mismatch_class recomputed = 49)
ok: evidence/java/legacy-record-adjudications.json adjudicates records 1-49, each bound to its record by recomputed identity, record digest and a unique verbatim rationale quote (records_without_ac3_class recomputed = 0 of 59)
ok: evidence/governance/owner-decision-digests.json equals the derivation and 7 governance record digest(s) recomputed from the protected store and matched
```

and `oracle-hierarchy-gates`, whose census is the one
`OA-oracle-census-anchor` is about, printed byte-identically to the line round 4
quoted:

```
oraclerankctl: 640 propositions adjudicated; 589 Java/Rust agreements, 39 of them overridden by a higher oracle and every one enrolled in evidence/oracle-hierarchy/adjudication-register.json
```

**No owner gate was triggered by this run or by anything else in this round.**
No AWS host was provisioned, no benchmark ran, no Autobahn leg ran, no label was
added to any pull request, and no held-out tier was generated or read.

Sections 1 to 5 and 7 of this record were written before this run and are
unchanged by it; this section and two corrections elsewhere were written after
it, so `record-guard` and `plan-guard` were re-run over the final text and both
are quoted again at the end of section 7.

## 7. Process

- Worked only in `/home/user/vjwp-attack5`. `.quarantine` is a symlink there and
  was never staged; `git status` was read before every commit and no `git add
  -A` was used.
- Every mutant was built before it was scored. One candidate mutation — the
  shared owner-decision citation appended to sequence 59's rationale — was
  refused by the delta validator for overrunning the rationale bound, and it is
  recorded above as a NON-RESULT rather than as a survivor.
- One reading was discarded: an early A2 run took its exit code from the end of
  a `tail` pipeline, which reported success while the program under it had
  failed. It was re-taken with the exit code captured from the program itself.
- `df -h /` before believing anything: 78% used, 8.5G free, unchanged across the
  round.
- The record's own gates: `record-guard` and `plan-guard` were re-run over the
  FINAL text of this file, after section 6 was written into it.

  ```
  gate=record-content-precondition mode=precondition records=1 result=PASS
  gate=record-content-precondition step=selfcheck cases=16 firing=8 silent=8 result=PASS
  gate=record-prose step=census cardinality_sentences=268 with_enumerable_population=13 no_enumerable_population=255 bound=13 covered=0 undispositioned=0
  gate=record-prose result=PASS
  ```

  The line COUNT this record reports moves every time this file is edited and
  is deliberately not quoted here; the verdicts are what the gate decides on.
- The full suite was re-run after the section 1b and 1c corrections, so the
  exit code in section 6 is over the tree as pushed and not over an earlier
  one.

- `internal/lab` has one test that fails on this platform,
  `TestControlledCanaryRequestIsClosedAndRequiresAuthenticatedPromotions`
  (`CONTROLLED_CANARY requires Darwin sandbox-exec`). I established it fails
  identically on the untouched base worktree before attributing it to the
  platform rather than to my change.

## 8. The shape, five rounds on

Four rounds defeated every gate anyone attacked, and this one defeated both
rules it was pointed at. But the two defects here are smaller than round 4's,
and both are the same two shapes the brief predicted in advance — a set that was
short by one term, and a number checked against itself. Nothing new about how
these gates fail was learned. The residue this round leaves is not another
adversarial round: it is the open owner actions, which no round can close.
