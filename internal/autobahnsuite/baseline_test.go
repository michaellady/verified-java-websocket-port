package autobahnsuite

// Tests for the amended AC3 bar and for the binding of the committed
// Java-versus-Rust comparison document to the runs it describes.
//
// Every negative case below was RUN AGAINST THE CODE BEFORE THE CHECK IT
// EXERCISES EXISTED, and observed to pass. The readings are recorded in
// drafts/self-review/us019-native-run-round-1.md. None of these is a check
// that reports clean because the tree happens to be fine.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// nativeSources are the four legs of the native x86_64 run: the port and the
// pinned Java baseline, each in both Autobahn modes, executed on one host
// against one manifest.
func nativeBase(root string) string {
	return filepath.Join(root, "evidence", "autobahn", "native-x86_64-provenance")
}

func nativeIndex(root, leg string) string {
	return filepath.Join(nativeBase(root), leg, "index.json")
}

func ledgerPath(root string) string {
	return filepath.Join(root, "evidence", "java", "behavior-delta-ledger.json")
}

func registerPath(root string) string {
	return filepath.Join(root, filepath.FromSlash(DivergenceRegisterPath))
}

// nativeAgreement builds one role's comparison from the committed native run.
func nativeAgreement(t *testing.T, root string, role Role, subjectLeg, baselineLeg string) *Agreement {
	t.Helper()
	manifest, err := BuildManifest(devSources(root))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	mustExist(t, nativeIndex(root, subjectLeg))
	mustExist(t, nativeIndex(root, baselineLeg))
	mustExist(t, registerPath(root))
	register, err := ReadDivergenceRegister(registerPath(root))
	if err != nil {
		t.Fatalf("ReadDivergenceRegister: %v", err)
	}
	agreement, err := CompareToBaseline(manifest, role,
		nativeIndex(root, subjectLeg), nativeIndex(root, baselineLeg), register)
	if err != nil {
		t.Fatalf("CompareToBaseline: %v", err)
	}
	return agreement
}

func nativeLedgers(t *testing.T, root, subjectLeg, baselineLeg string) (*Ledger, *Ledger) {
	t.Helper()
	manifest, err := BuildManifest(devSources(root))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	subject, err := Reconcile(manifest, nativeIndex(root, subjectLeg),
		filepath.Join(nativeBase(root), subjectLeg, "cases"), nil)
	if err != nil {
		t.Fatalf("Reconcile subject: %v", err)
	}
	baseline, err := Reconcile(manifest, nativeIndex(root, baselineLeg),
		filepath.Join(nativeBase(root), baselineLeg, "cases"), nil)
	if err != nil {
		t.Fatalf("Reconcile baseline: %v", err)
	}
	return subject, baseline
}

// TestAmendedAC3IsMeasuredAgainstThePinnedJavaBaseline is the positive
// reading: what the committed native run actually scores under the amended
// bar, derived rather than quoted.
//
// The owner's decision text records "client 245/247, server 246/247". Those
// figures came from the earlier emulated run and are NOT what this tree
// holds: both roles measure 246 agreeing of 247, with the single residual
// difference at case 5.15 in both. The numbers here are printed from the
// comparison so the record can never again quote a figure nobody read.
func TestAmendedAC3IsMeasuredAgainstThePinnedJavaBaseline(t *testing.T) {
	root := repoRoot(t)
	for _, leg := range []struct {
		role              Role
		subject, baseline string
	}{
		{RoleClient, "rust/fuzzingserver-run1", "java/fuzzingserver-run1"},
		{RoleServer, "rust/fuzzingclient-run1", "java/fuzzingclient-run1"},
	} {
		t.Run(string(leg.role), func(t *testing.T) {
			agreement := nativeAgreement(t, root, leg.role, leg.subject, leg.baseline)
			if !agreement.Partitions {
				t.Fatalf("the comparison does not partition the manifest: %v", agreement.Identities)
			}
			if agreement.Unobserved != 0 {
				t.Fatalf("%d cases were not scored by both runs", agreement.Unobserved)
			}
			if agreement.SubjectAgent == agreement.BaselineAgent {
				t.Fatalf("subject and baseline are the same agent %q", agreement.SubjectAgent)
			}
			subjectLedger, baselineLedger := nativeLedgers(t, root, leg.subject, leg.baseline)
			verdict := DiscriminateAgainstBaseline(subjectLedger, baselineLedger, agreement)
			t.Logf("%s: agree=%d stricter=%d weaker=%d differ=%d ledgered=%d unledgered=%d verdict=%t",
				leg.role, agreement.Agree, agreement.SubjectStricter, agreement.SubjectWeaker,
				agreement.Differ, agreement.RegisteredDelta, agreement.UnregisteredDelta,
				verdict.AsExpected)
			if !verdict.AsExpected {
				t.Errorf("the amended AC3 bar is not met on the committed run: %s", verdict.Reason)
			}
			// The residual difference is real and must stay visible: it is
			// ledgered, not waived.
			if agreement.SubjectWeaker+agreement.Differ == 0 {
				t.Error("this run is known to carry one residual difference (5.15); " +
					"measuring zero means the comparison stopped discriminating")
			}
			if agreement.UnregisteredDelta != 0 {
				t.Errorf("%d divergences are not accounted for by the register: %v",
					agreement.UnregisteredDelta, agreement.DivergenceDetail)
			}
			// The LITERAL bar stays computed and stays negative. The
			// amendment did not make the port a strict pass, and this
			// records that both readings coexist.
			if literal := Discriminate(SubjectUnderTest, subjectLedger); literal.AsExpected {
				t.Error("the literal strict-pass reading must remain NEGATIVE on this run")
			}
		})
	}
}

// TestAComparisonWithItselfProvesNothing is the vacuity guard, and it is the
// sharpest check here. Any report agrees with itself on every case, so
// without this the amended bar would be satisfiable by pointing both sides
// at the same run — a check that cannot fail.
func TestAComparisonWithItselfProvesNothing(t *testing.T) {
	root := repoRoot(t)
	manifest, err := BuildManifest(devSources(root))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	register, err := ReadDivergenceRegister(registerPath(root))
	if err != nil {
		t.Fatalf("ReadDivergenceRegister: %v", err)
	}
	self := nativeIndex(root, "rust/fuzzingserver-run1")
	agreement, err := CompareToBaseline(manifest, RoleClient, self, self, register)
	if err != nil {
		t.Fatalf("CompareToBaseline: %v", err)
	}
	// Measured, so the reason the guard is needed is visible rather than
	// asserted: comparing a run with itself scores a perfect agreement.
	if agreement.Agree != len(manifest.Cases) {
		t.Fatalf("a self-comparison should agree on every case; got %d of %d",
			agreement.Agree, len(manifest.Cases))
	}
	subjectLedger, _ := nativeLedgers(t, root, "rust/fuzzingserver-run1", "java/fuzzingserver-run1")
	verdict := DiscriminateAgainstBaseline(subjectLedger, subjectLedger, agreement)
	if verdict.AsExpected {
		t.Errorf("a run compared with ITSELF satisfied the amended AC3 bar, which makes the "+
			"bar vacuous: %s", verdict.Reason)
	}
}

// TestAnUnregisteredDivergenceFailsTheAmendedBar empties the register and
// requires the verdict to go negative. "Analysed and ledgered" is the owner
// decision's own condition; without this the phrase would be prose beside the
// check.
func TestAnUnregisteredDivergenceFailsTheAmendedBar(t *testing.T) {
	root := repoRoot(t)
	manifest, err := BuildManifest(devSources(root))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	agreement, err := CompareToBaseline(manifest, RoleClient,
		nativeIndex(root, "rust/fuzzingserver-run1"),
		nativeIndex(root, "java/fuzzingserver-run1"), &DivergenceRegister{})
	if err != nil {
		t.Fatalf("CompareToBaseline: %v", err)
	}
	if agreement.UnregisteredDelta != 1 {
		t.Fatalf("expected the one residual difference to become unregistered; got %d",
			agreement.UnregisteredDelta)
	}
	subjectLedger, baselineLedger := nativeLedgers(t, root,
		"rust/fuzzingserver-run1", "java/fuzzingserver-run1")
	if verdict := DiscriminateAgainstBaseline(subjectLedger, baselineLedger, agreement); verdict.AsExpected {
		t.Errorf("a divergence nothing accounts for satisfied the amended bar: %s", verdict.Reason)
	}
}

// TestARegisterEntryMustMatchTheObservedClasses stops an entry from
// outliving the reading it describes: the register states a pair of behavior
// classes, and the runs must actually show that pair.
func TestARegisterEntryMustMatchTheObservedClasses(t *testing.T) {
	root := repoRoot(t)
	manifest, err := BuildManifest(devSources(root))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	register, err := ReadDivergenceRegister(registerPath(root))
	if err != nil {
		t.Fatalf("ReadDivergenceRegister: %v", err)
	}
	// The committed register is exact for both roles.
	for _, leg := range []struct {
		role              Role
		subject, baseline string
	}{
		{RoleClient, "rust/fuzzingserver-run1", "java/fuzzingserver-run1"},
		{RoleServer, "rust/fuzzingclient-run1", "java/fuzzingclient-run1"},
	} {
		agreement, err := CompareToBaseline(manifest, leg.role,
			nativeIndex(root, leg.subject), nativeIndex(root, leg.baseline), register)
		if err != nil {
			t.Fatalf("CompareToBaseline: %v", err)
		}
		for _, problem := range VerifyRegisterIsExact(register, agreement) {
			t.Errorf("register is not exact for %s: %s", leg.role, problem)
		}
	}
	// A STALE entry — one naming a case the runs agree on, with every real
	// divergence still registered — must be refused on its own. Isolating it
	// matters: with the real divergence also unregistered, the missing-entry
	// direction fires and hides whether the stale direction works at all.
	// Measured: deleting the stale-entry arm left the earlier version of
	// this test green, because its probe removed 5.15 at the same time.
	t.Run("a stale entry naming an agreeing case", func(t *testing.T) {
		stale := &DivergenceRegister{Entries: append([]DivergenceEntry(nil), register.Entries...)}
		stale.Entries = append(stale.Entries, DivergenceEntry{
			CaseID:           "1.1.1",
			Role:             RoleClient,
			SubjectBehavior:  BehaviorNonStrict,
			BaselineBehavior: BehaviorOK,
			LedgerDeltaID:    "delta-7270836da2cecf6acc2a8e0d2a4fd8f15873f8f8d588494c2789358d369c5f0d",
			LedgerSequence:   47,
			Rationale:        "planted stale entry",
		})
		agreement, err := CompareToBaseline(manifest, RoleClient,
			nativeIndex(root, "rust/fuzzingserver-run1"),
			nativeIndex(root, "java/fuzzingserver-run1"), stale)
		if err != nil {
			t.Fatalf("CompareToBaseline: %v", err)
		}
		if agreement.UnregisteredDelta != 0 {
			t.Fatalf("this probe must isolate the STALE direction; %d divergences are also "+
				"unregistered", agreement.UnregisteredDelta)
		}
		problems := VerifyRegisterIsExact(stale, agreement)
		if len(problems) == 0 {
			t.Error("a register entry for a case the runs AGREE on produced no problem: a stale " +
				"entry is a standing licence for a future regression on that case")
		}
	})

	// A stated class the runs do not show must be refused, in both
	// directions: the entry no longer describes an observation.
	for _, mutate := range []func(*DivergenceEntry){
		func(entry *DivergenceEntry) { entry.SubjectBehavior = BehaviorOK },
		func(entry *DivergenceEntry) { entry.BaselineBehavior = BehaviorFailed },
		func(entry *DivergenceEntry) { entry.CaseID = "1.1.1" },
	} {
		forged := &DivergenceRegister{Entries: append([]DivergenceEntry(nil), register.Entries...)}
		mutate(&forged.Entries[0])
		agreement, err := CompareToBaseline(manifest, RoleClient,
			nativeIndex(root, "rust/fuzzingserver-run1"),
			nativeIndex(root, "java/fuzzingserver-run1"), forged)
		if err != nil {
			t.Fatalf("CompareToBaseline: %v", err)
		}
		if len(VerifyRegisterIsExact(forged, agreement)) == 0 {
			t.Errorf("a register entry that does not match the runs produced no problem: %+v",
				forged.Entries[0])
		}
		subjectLedger, baselineLedger := nativeLedgers(t, root,
			"rust/fuzzingserver-run1", "java/fuzzingserver-run1")
		if verdict := DiscriminateAgainstBaseline(subjectLedger, baselineLedger, agreement); verdict.AsExpected {
			t.Errorf("a mismatched register entry satisfied the amended bar: %s", verdict.Reason)
		}
	}
}

// TestEveryRegisterEntryResolvesInTheLedger binds the register's analysis
// claim to the behavior-delta ledger's own bytes: the named record must
// exist at the named sequence and must cite the Autobahn case.
func TestEveryRegisterEntryResolvesInTheLedger(t *testing.T) {
	root := repoRoot(t)
	register, err := ReadDivergenceRegister(registerPath(root))
	if err != nil {
		t.Fatalf("ReadDivergenceRegister: %v", err)
	}
	if len(register.Entries) == 0 {
		t.Fatal("the committed register is empty; this gate would test nothing")
	}
	problems, err := VerifyRegisterAgainstLedger(register, ledgerPath(root))
	if err != nil {
		t.Fatalf("VerifyRegisterAgainstLedger: %v", err)
	}
	for _, problem := range problems {
		t.Errorf("register does not resolve in the ledger: %s", problem)
	}
	// Polarity, three ways a forged reference can be wrong.
	for name, mutate := range map[string]func(*DivergenceEntry){
		"a sequence the ledger does not hold": func(e *DivergenceEntry) { e.LedgerSequence = 9999 },
		"a delta id that is not at that sequence": func(e *DivergenceEntry) {
			e.LedgerDeltaID = "delta-0000000000000000000000000000000000000000000000000000000000000000"
		},
		"a record that does not cite this case": func(e *DivergenceEntry) {
			// Sequence 47 is a real record; it cites 1.1.1, not 5.15.
			e.LedgerSequence = 47
			e.LedgerDeltaID = "delta-7270836da2cecf6acc2a8e0d2a4fd8f15873f8f8d588494c2789358d369c5f0d"
		},
	} {
		t.Run(name, func(t *testing.T) {
			forged := &DivergenceRegister{Entries: append([]DivergenceEntry(nil), register.Entries...)}
			mutate(&forged.Entries[0])
			problems, err := VerifyRegisterAgainstLedger(forged, ledgerPath(root))
			if err != nil {
				t.Fatalf("VerifyRegisterAgainstLedger: %v", err)
			}
			if len(problems) == 0 {
				t.Errorf("a forged ledger reference produced no problem: %+v", forged.Entries[0])
			}
		})
	}
}

// TestAPortRegressionFailsTheAmendedBar plants a real regression: a case the
// baseline scores OK is rewritten to FAILED in the subject's index. The
// amended bar must refuse it. Agreement with Java is a two-sided condition,
// and this is the side that matters.
func TestAPortRegressionFailsTheAmendedBar(t *testing.T) {
	root := repoRoot(t)
	manifest, err := BuildManifest(devSources(root))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	register, err := ReadDivergenceRegister(registerPath(root))
	if err != nil {
		t.Fatalf("ReadDivergenceRegister: %v", err)
	}
	raw, err := os.ReadFile(nativeIndex(root, "rust/fuzzingserver-run1"))
	if err != nil {
		t.Fatalf("read subject index: %v", err)
	}
	var byAgent map[string]map[string]map[string]any
	if err := json.Unmarshal(raw, &byAgent); err != nil {
		t.Fatalf("parse subject index: %v", err)
	}
	planted := ""
	for agent, cases := range byAgent {
		// 1.1.1 is an OK case in both runs, so breaking it is a regression
		// rather than an existing difference.
		entry, present := cases["1.1.1"]
		if !present {
			t.Fatalf("case 1.1.1 is absent from %s; this probe is stale", agent)
		}
		if entry["behavior"] != BehaviorOK {
			t.Fatalf("case 1.1.1 is %v, not OK; this probe is stale", entry["behavior"])
		}
		entry["behavior"] = BehaviorFailed
		planted = agent
	}
	forged := filepath.Join(t.TempDir(), "index.json")
	encoded, err := json.Marshal(byAgent)
	if err != nil {
		t.Fatalf("encode forged index: %v", err)
	}
	if err := os.WriteFile(forged, encoded, 0o600); err != nil {
		t.Fatalf("write forged index: %v", err)
	}
	agreement, err := CompareToBaseline(manifest, RoleClient, forged,
		nativeIndex(root, "java/fuzzingserver-run1"), register)
	if err != nil {
		t.Fatalf("CompareToBaseline: %v", err)
	}
	if agreement.SubjectWeaker < 2 {
		t.Fatalf("planting a regression in %s should have produced a second weaker case; got %d",
			planted, agreement.SubjectWeaker)
	}
	subjectLedger, baselineLedger := nativeLedgers(t, root,
		"rust/fuzzingserver-run1", "java/fuzzingserver-run1")
	if agreement.UnregisteredDelta != 1 {
		t.Errorf("the planted regression should be UNREGISTERED; got %d unregistered (%v)",
			agreement.UnregisteredDelta, agreement.DivergenceDetail)
	}
	if verdict := DiscriminateAgainstBaseline(subjectLedger, baselineLedger, agreement); verdict.AsExpected {
		t.Errorf("a planted regression on a case Java passes satisfied the amended bar: %s",
			verdict.Reason)
	}
}

// TestAnIncompleteBaselineCannotBeAgreedWith covers the absence-of-evidence
// direction: a truncated or empty baseline must never read as agreement.
func TestAnIncompleteBaselineCannotBeAgreedWith(t *testing.T) {
	root := repoRoot(t)
	manifest, err := BuildManifest(devSources(root))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	register, err := ReadDivergenceRegister(registerPath(root))
	if err != nil {
		t.Fatalf("ReadDivergenceRegister: %v", err)
	}
	empty := filepath.Join(t.TempDir(), "index.json")
	if err := os.WriteFile(empty,
		[]byte(`{"verified-java-websocket-port-1.6.0":{}}`), 0o600); err != nil {
		t.Fatalf("write empty baseline: %v", err)
	}
	agreement, err := CompareToBaseline(manifest, RoleClient,
		nativeIndex(root, "rust/fuzzingserver-run1"), empty, register)
	if err != nil {
		t.Fatalf("CompareToBaseline: %v", err)
	}
	if agreement.Unobserved != len(manifest.Cases) {
		t.Fatalf("an empty baseline should leave every case unobserved; got %d",
			agreement.Unobserved)
	}
	subjectLedger, _ := nativeLedgers(t, root, "rust/fuzzingserver-run1", "java/fuzzingserver-run1")
	emptyLedger, err := Reconcile(manifest, empty, "", nil)
	if err != nil {
		t.Fatalf("Reconcile empty baseline: %v", err)
	}
	if verdict := DiscriminateAgainstBaseline(subjectLedger, emptyLedger, agreement); verdict.AsExpected {
		t.Errorf("an empty baseline satisfied the amended bar: %s", verdict.Reason)
	}
}

// nativeLegs maps the comparison document's behavior columns to the index
// each one must be re-derived from.
func nativeLegs(root string) map[string]string {
	return map[string]string{
		"rust_client_behavior": nativeIndex(root, "rust/fuzzingserver-run1"),
		"java_client_behavior": nativeIndex(root, "java/fuzzingserver-run1"),
		"rust_server_behavior": nativeIndex(root, "rust/fuzzingclient-run1"),
		"java_server_behavior": nativeIndex(root, "java/fuzzingclient-run1"),
	}
}

// TestTheCommittedComparisonDocumentDescribesTheRuns gives the generated
// comparison a consumer. Before this it had none: it could be edited,
// truncated, or refreshed from another run and no gate would notice.
func TestTheCommittedComparisonDocumentDescribesTheRuns(t *testing.T) {
	root := repoRoot(t)
	manifest, err := BuildManifest(devSources(root))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	path := filepath.Join(root, filepath.FromSlash(ComparisonDocumentPath))
	mustExist(t, path)
	findings, err := VerifyComparisonDocument(path, manifest, nativeLegs(root))
	if err != nil {
		t.Fatalf("VerifyComparisonDocument: %v", err)
	}
	for _, finding := range findings {
		t.Errorf("comparison document disagrees with the runs: case=%s field=%s %s",
			finding.CaseID, finding.Field, finding.Detail)
	}
}

// TestTheComparisonCheckReadsTheRunsNotTheDocument proves the document check
// is not self-referential. Feeding it the committed document with the LEGS
// pointed at a different run's indexes must produce findings: the values are
// re-derived from the indexes, so a document that describes run A cannot
// verify against run B.
//
// This exists because the obvious deletion probe (removing the value
// comparison) breaks the build rather than turning a test green, and a
// compile error is not evidence that a check discriminates.
func TestTheComparisonCheckReadsTheRunsNotTheDocument(t *testing.T) {
	root := repoRoot(t)
	manifest, err := BuildManifest(devSources(root))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	path := filepath.Join(root, filepath.FromSlash(ComparisonDocumentPath))
	// Every leg pointed at the NEGATIVE CONTROL's report: a genuine Autobahn
	// run, of a different subject. The document's values describe the port.
	control := filepath.Join(root, "evidence", "autobahn", "dev-aarch64-nonauthoritative",
		"discrimination", "negative-control-fuzzingclient", "index.json")
	mustExist(t, control)
	findings, err := VerifyComparisonDocument(path, manifest, map[string]string{
		"rust_client_behavior": control,
		"java_client_behavior": control,
		"rust_server_behavior": control,
		"java_server_behavior": control,
	})
	if err != nil {
		return // a hard refusal is also a refusal
	}
	if len(findings) == 0 {
		t.Error("the committed comparison document verified against a DIFFERENT subject's run, " +
			"so its values are not being read from the runs at all")
	}
}

// TestATamperedComparisonDocumentIsRefused is the polarity of the check
// above, in every direction a forger has: a behavior value edited, a row
// deleted, a row's difference hidden from the summary list, and an agent
// name relabelled.
func TestATamperedComparisonDocumentIsRefused(t *testing.T) {
	root := repoRoot(t)
	manifest, err := BuildManifest(devSources(root))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	path := filepath.Join(root, filepath.FromSlash(ComparisonDocumentPath))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read comparison document: %v", err)
	}

	for _, testCase := range []struct {
		name   string
		mutate func(t *testing.T, document map[string]any)
	}{
		{
			name: "a behavior value is edited to hide the residual difference",
			mutate: func(t *testing.T, document map[string]any) {
				for _, row := range document["cases"].([]any) {
					entry := row.(map[string]any)
					if entry["case_id"] == "5.15" {
						entry["rust_client_behavior"] = BehaviorOK
						entry["rust_server_behavior"] = BehaviorOK
						return
					}
				}
				t.Fatal("case 5.15 not present; this probe is stale")
			},
		},
		{
			// THE ISOLATING PROBE for the value comparison. Both roles' values
			// on case 3.2 are NON-STRICT in both runs, so rewriting BOTH to OK
			// keeps the row internally consistent, keeps it correctly absent
			// from the difference list, and changes no count. Nothing but a
			// comparison against the runs' own indexes can see it.
			//
			// Measured: with the value comparison deleted (and the function
			// still compiling), every OTHER case in this table stayed red
			// through a different check, and the whole file went green. This
			// probe is what makes the deletion visible.
			name: "a behavior value is edited where nothing else disagrees",
			mutate: func(t *testing.T, document map[string]any) {
				for _, row := range document["cases"].([]any) {
					entry := row.(map[string]any)
					if entry["case_id"] != "3.2" {
						continue
					}
					for _, column := range []string{
						"rust_client_behavior", "java_client_behavior",
						"rust_server_behavior", "java_server_behavior",
					} {
						if entry[column] != BehaviorNonStrict {
							t.Fatalf("case 3.2 %s is %v, not NON-STRICT; this probe is stale",
								column, entry[column])
						}
						entry[column] = BehaviorOK
					}
					return
				}
				t.Fatal("case 3.2 not present; this probe is stale")
			},
		},
		{
			name: "a case row is deleted",
			mutate: func(t *testing.T, document map[string]any) {
				rows := document["cases"].([]any)
				document["cases"] = rows[1:]
			},
		},
		{
			name: "a real difference is dropped from the difference list",
			mutate: func(t *testing.T, document map[string]any) {
				document["behavior_differences"] = map[string]any{
					"client_role": []any{},
					"server_role": []any{},
				}
			},
		},
		{
			name: "an agent name is relabelled",
			mutate: func(t *testing.T, document map[string]any) {
				agents := document["agents"].(map[string]any)
				agents["java_client_role"] = "verified-rust-ws-testee-us019"
			},
		},
		{
			name: "the compared count no longer matches the rows",
			mutate: func(t *testing.T, document map[string]any) {
				document["compared_case_count"] = float64(246)
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(raw, &document); err != nil {
				t.Fatalf("decode: %v", err)
			}
			testCase.mutate(t, document)
			encoded, err := json.Marshal(document)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			forged := filepath.Join(t.TempDir(), "comparison.json")
			if err := os.WriteFile(forged, encoded, 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			findings, err := VerifyComparisonDocument(forged, manifest, nativeLegs(root))
			if err != nil {
				return // a hard parse refusal is also a refusal
			}
			if len(findings) == 0 {
				t.Error("the tampered comparison document produced no finding")
			}
		})
	}
}
