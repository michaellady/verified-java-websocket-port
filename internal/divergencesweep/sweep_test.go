package divergencesweep

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	absolute, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return absolute
}

// The committed sweep document must equal what the run reports produce. This
// is the consumer the artifact exists for: a document nobody recomputes is a
// number somebody typed.
func TestCommittedDocumentAgreesWithTheRunReports(t *testing.T) {
	if err := Verify(repoRoot(t)); err != nil {
		t.Fatalf("committed sweep document: %v", err)
	}
}

// Every difference the sweep measures must be attributed to a named class. An
// unclaimed difference is a divergence nobody has looked at, which is exactly
// the blindness this sweep was built to remove.
func TestEveryMeasuredDifferenceIsExplainedByAClass(t *testing.T) {
	_, document, err := Recompute(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	accounting := document.Accounting
	if accounting.TotalDifferences == 0 {
		t.Fatal("the sweep measured no differences at all, which cannot be right for this run")
	}
	if accounting.Unclaimed != 0 {
		t.Fatalf("%d of %d measured differences are claimed by no divergence class; first: %v",
			accounting.Unclaimed, accounting.TotalDifferences, accounting.UnclaimedExamples)
	}
	if accounting.ClaimedByAClass != accounting.TotalDifferences {
		t.Fatalf("claimed %d of %d differences", accounting.ClaimedByAClass, accounting.TotalDifferences)
	}
}

// Every dimension's verdict counts must partition the case set, on both roles.
// Build asserts this too; asserting it here as well means a Build that stopped
// asserting it does not go unnoticed.
func TestVerdictCountsPartitionTheCaseSet(t *testing.T) {
	_, document, err := Recompute(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range document.Measurements {
		if role.CaseCount != ExpectedCaseCount {
			t.Fatalf("%s role walked %d cases, want %d", role.SubjectRole, role.CaseCount, ExpectedCaseCount)
		}
		for _, dimension := range role.Dimensions {
			sum := dimension.Agree + dimension.PortAbsentJavaPresent +
				dimension.JavaAbsentPortPresent + dimension.BothPresentDiffer
			if sum != role.CaseCount {
				t.Fatalf("%s role, dimension %s: %d+%d+%d+%d = %d, want %d",
					role.SubjectRole, dimension.Dimension, dimension.Agree,
					dimension.PortAbsentJavaPresent, dimension.JavaAbsentPortPresent,
					dimension.BothPresentDiffer, sum, role.CaseCount)
			}
			if sum != dimension.PartitionSum {
				t.Fatalf("%s role, dimension %s: recorded partition sum %d, recomputed %d",
					role.SubjectRole, dimension.Dimension, dimension.PartitionSum, sum)
			}
			if len(dimension.DifferingCases) != dimension.TotalDifferences {
				t.Fatalf("%s role, dimension %s: %d differing cases listed, %d counted",
					role.SubjectRole, dimension.Dimension,
					len(dimension.DifferingCases), dimension.TotalDifferences)
			}
		}
		for _, group := range role.Groups {
			if group.PartitionSum != role.CaseCount {
				t.Fatalf("%s role, group %s: %d + %d != %d",
					role.SubjectRole, group.Group, group.CasesAgreeingOnEveryDimension,
					group.CasesDifferingSomewhere, role.CaseCount)
			}
		}
	}
}

// Every key the reports carry is classified. A run that grew a field the sweep
// does not know about is refused rather than silently under-compared.
func TestFieldPartitionCoversEveryReportedKey(t *testing.T) {
	_, document, err := Recompute(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	partition := document.FieldPartition
	total := len(partition.Compared) + len(partition.Invariant) + len(partition.NotComparable)
	if total != partition.ObservedFieldCount {
		t.Fatalf("field partition: %d classified, %d observed", total, partition.ObservedFieldCount)
	}
	if partition.ObservedFieldCount != len(partition.ObservedFields) {
		t.Fatalf("field partition: count %d, list %d", partition.ObservedFieldCount, len(partition.ObservedFields))
	}
}

// checkFieldPartition must refuse both an unclassified field and a classified
// field the reports do not carry. Without this probe the partition check is
// only ever exercised on the passing input.
func TestFieldPartitionRefusesBothDirections(t *testing.T) {
	_, document, err := Recompute(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	observed := document.FieldPartition.ObservedFields
	if err := checkFieldPartition(observed); err != nil {
		t.Fatalf("the real field set must pass: %v", err)
	}
	extra := append(append([]string(nil), observed...), "someFutureAutobahnField")
	if err := checkFieldPartition(extra); err == nil {
		t.Fatal("a report field nobody classified was accepted")
	}
	shorter := append([]string(nil), observed[1:]...)
	if err := checkFieldPartition(shorter); err == nil {
		t.Fatalf("a classified field the reports do not carry (%s) was accepted", observed[0])
	}
}

// The subject role must be read out of the reports, not taken from the leg
// name. Declaring a leg with the wrong role must be refused, because a
// reversed mapping would put every close finding on the wrong role and change
// no count at all.
func TestLoadLegRefusesAMisdeclaredSubjectRole(t *testing.T) {
	root := repoRoot(t)
	good := LegSpec{Peer: "rust", Directory: "fuzzingclient-run1", SubjectRole: "server"}
	if _, err := LoadLeg(root, good); err != nil {
		t.Fatalf("the correctly declared leg must load: %v", err)
	}
	bad := LegSpec{Peer: "rust", Directory: "fuzzingclient-run1", SubjectRole: "client"}
	if _, err := LoadLeg(root, bad); err == nil {
		t.Fatal("a leg declared with the wrong subject role was accepted")
	}
}

// DIV-04 says an existing ledger record already carries it. That claim is
// resolved in the ledger's own bytes, and the case set it claims must equal
// the committed behaviour-class divergence register's, in both directions.
func TestAlreadyLedgeredClassResolvesInTheLedgerAndTheRegister(t *testing.T) {
	root := repoRoot(t)
	_, document, err := Recompute(root)
	if err != nil {
		t.Fatal(err)
	}
	refs, err := LedgerSubjectRefs(root)
	if err != nil {
		t.Fatal(err)
	}
	registered, sequences, err := RegisteredBehaviourClassDivergences(root)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, class := range document.Classes {
		if class.ExistingLedgerSubjectRef == "" {
			continue
		}
		found++
		sequence, ok := refs[class.ExistingLedgerSubjectRef]
		if !ok {
			t.Fatalf("class %s cites ledger subject_ref %q, which the committed ledger does not carry",
				class.ID, class.ExistingLedgerSubjectRef)
		}
		if sequence != class.ExistingLedgerSequence {
			t.Fatalf("class %s cites ledger sequence %d, the ledger carries that subject_ref at %d",
				class.ID, class.ExistingLedgerSequence, sequence)
		}
		for role, cases := range class.Cases {
			if !reflect.DeepEqual(cases, registered[role]) {
				t.Fatalf("class %s, %s role: measured cases %v, the committed register records %v",
					class.ID, role, cases, registered[role])
			}
			for _, caseID := range cases {
				if got := sequences[role+"/"+caseID]; got != class.ExistingLedgerSequence {
					t.Fatalf("class %s, %s role, case %s: the register cites ledger sequence %d, the class cites %d",
						class.ID, role, caseID, got, class.ExistingLedgerSequence)
				}
			}
		}
	}
	if found == 0 {
		t.Fatal("no class claims an existing ledger record, so this check proved nothing")
	}
}

// Every class recommended for a ledger record proposes a subject_ref that the
// committed ledger does NOT yet carry. This is a tripwire on purpose: the day
// a proposal lands, this fails and the sweep document's recommendation has to
// be brought up to date rather than quietly going stale.
func TestProposedLedgerRecordsHaveNotLandedYet(t *testing.T) {
	root := repoRoot(t)
	_, document, err := Recompute(root)
	if err != nil {
		t.Fatal(err)
	}
	refs, err := LedgerSubjectRefs(root)
	if err != nil {
		t.Fatal(err)
	}
	proposed := 0
	for _, class := range document.Classes {
		if class.ProposedLedgerSubjectRef == "" {
			continue
		}
		proposed++
		if sequence, landed := refs[class.ProposedLedgerSubjectRef]; landed {
			t.Fatalf("class %s proposes subject_ref %q and the committed ledger now carries it at sequence %d: the proposal has landed, so update this sweep's recommendation and drafts/ledger-proposals/",
				class.ID, class.ProposedLedgerSubjectRef, sequence)
		}
	}
	if proposed == 0 {
		t.Fatal("no class proposes a ledger record, so this check proved nothing")
	}
}

// DIV06ClosureDraft is where the closure of DIV-06 is recorded for the owner.
// The sweep document itself is NOT edited when a divergence is fixed: it is a
// measurement of one run against one build (`subject_commit` 518b77aa), and
// that measurement stays true of that build forever. What changed is the
// PORT, and that change needs its own record.
const DIV06ClosureDraft = "drafts/ledger-proposals/div06-handshake-response.json"

// DIV-06 said the port's 101 response omitted the two fields shipped Java
// adds and did not sort its header names. That claim was about a file in this
// tree, so it is checked against that file — and it is now CLOSED: the port
// site DIV-06 names writes all five of Java's fields, in Java's order.
//
// This check used to be a tripwire that fired when the port was fixed. It has
// been turned around rather than deleted, because the reason it existed has
// not gone away: the sweep document describes a port, the port can move under
// it, and nothing else in this package reads the port's source. It now fails
// if the fix REGRESSES, if the fix stops being recorded, or if it stops
// reading what it thinks it is reading.
//
// It asserts source structure, not behaviour. The behaviour is proved where
// it can be observed: rust/ws-core/tests/handshake_server_response.rs pins the
// head byte-for-byte against the pinned jar's own output, and
// rust/ws-testee/tests/loopback.rs reads it off a real socket.
func TestDIV06IsClosedInThePortSourceItNames(t *testing.T) {
	root := repoRoot(t)
	source, err := os.ReadFile(filepath.Join(root, "rust/ws-core/src/handshake/server.rs"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	start := strings.Index(text, "fn accept_response(")
	if start < 0 {
		t.Fatal("rust/ws-core/src/handshake/server.rs no longer defines accept_response, which DIV-06 names as the port site")
	}
	end := strings.Index(text[start:], "\n}\n")
	if end < 0 {
		t.Fatal("could not delimit accept_response")
	}
	body := text[start : start+end]

	// Java's five response fields, in the order String.CASE_INSENSITIVE_ORDER
	// puts them in (HandshakedataImpl1.java:50 -> Draft.java:275-283). The
	// port writes them in that same order, so their positions in the source
	// must be strictly increasing.
	previous := -1
	for _, field := range []string{"Connection", "Date", "Sec-WebSocket-Accept", "Server", "Upgrade"} {
		at := strings.Index(body, field+": ")
		if at < 0 {
			t.Fatalf("accept_response no longer writes a %s field: DIV-06 was closed by making the port emit all five of Java's response fields (Draft_6455.java:431-452), and %s records that closure. This is a regression, not a new finding.",
				field, DIV06ClosureDraft)
		}
		if at <= previous {
			t.Fatalf("accept_response writes %s out of order: shipped Java emits Connection, Date, Sec-WebSocket-Accept, Server, Upgrade — case-insensitive alphabetical, because HandshakedataImpl1.java:50 is a TreeMap with String.CASE_INSENSITIVE_ORDER and Draft.java:275-283 writes its key set in iteration order",
				field)
		}
		previous = at
	}

	// The Connection VALUE is echoed from the request (Draft_6455.java:435-436),
	// not a literal. A hard-coded value would pass every check above and every
	// case the recorded Autobahn run contains, because the suite always sends
	// exactly "Connection: Upgrade".
	if strings.Contains(body, `b"Connection: Upgrade`) {
		t.Fatal("accept_response hard-codes Connection: Upgrade again. Draft_6455.java:435-436 is response.put(CONNECTION, request.getFieldValue(CONNECTION)) — the value is the REQUEST's, echoed. No case in the recorded run can catch this, which is why it is checked here.")
	}

	// The guard on this check reading what it thinks it is reading. If the
	// port site were renamed or emptied, every assertion above would still be
	// satisfiable by an empty body.
	if !strings.Contains(body, "HTTP/1.1 101 Web Socket Protocol Handshake") {
		t.Fatal("accept_response no longer writes the 101 status line, so this check is no longer reading what it thinks it is")
	}

	// And the closure must stay recorded. A fix whose record has been deleted
	// leaves the sweep document as the only surviving description of the port,
	// and that description is now stale by design.
	if _, err := os.Stat(filepath.Join(root, DIV06ClosureDraft)); err != nil {
		t.Fatalf("the port site DIV-06 names has been fixed but %s does not exist: %v. %s still reports DIV-06 as measured on subject_commit 518b77aa, which is correct for that run and no longer describes mainline; the closure needs its own record.",
			DIV06ClosureDraft, err, DocumentPath)
	}
}

// A committed document that has been edited away from the reports must be
// refused. Verify is the gate; this proves the gate closes.
func TestVerifyRefusesAnEditedDocument(t *testing.T) {
	root := t.TempDir()
	mirrorForProbe(t, repoRoot(t), root)
	if err := Verify(root); err != nil {
		t.Fatalf("the unmodified mirror must verify: %v", err)
	}
	path := filepath.Join(root, DocumentPath)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(data), `"total_differences": `, `"total_differences": 1`, 1)
	if edited == string(data) {
		t.Fatal("probe did not change the document")
	}
	if err := os.WriteFile(path, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Verify(root); err == nil {
		t.Fatal("a committed document edited away from the reports was accepted")
	}
}

// An edited report must be refused by the digest manifest before any
// comparison runs, and a planted or missing file must be refused too. Without
// these the whole sweep would happily describe a tampered tree.
func TestEvidenceIntegrityRefusesEditedPlantedAndMissingFiles(t *testing.T) {
	base := repoRoot(t)
	casePath := filepath.Join(EvidenceRoot, "rust/fuzzingclient-run1/cases/verified_rust_ws_testee_us019_case_3_1.json")

	t.Run("edited report", func(t *testing.T) {
		root := t.TempDir()
		mirrorForProbe(t, base, root)
		if _, err := VerifyEvidenceIntegrity(root); err != nil {
			t.Fatalf("the unmodified mirror must verify: %v", err)
		}
		data, err := os.ReadFile(filepath.Join(root, casePath))
		if err != nil {
			t.Fatal(err)
		}
		// resultClose is deliberate: the index does not repeat it and the
		// committed comparison document does not carry it, so NOTHING but the
		// digest manifest can refuse this edit. Editing a field another check
		// also binds would let this probe pass on that other check's back.
		edited := strings.Replace(string(data),
			`"resultClose": "Connection was properly closed"`,
			`"resultClose": "Connection was improperly closed"`, 1)
		if edited == string(data) {
			t.Fatal("probe did not change the report")
		}
		if err := os.WriteFile(filepath.Join(root, casePath), []byte(edited), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyEvidenceIntegrity(root); err == nil {
			t.Fatal("an edited per-case report was accepted")
		}
		_, err = Run(root)
		if err == nil {
			t.Fatal("the sweep ran over an edited per-case report")
		}
		if !strings.Contains(err.Error(), "the manifest pins") {
			t.Fatalf("the sweep refused the edited report, but not on the digest manifest: %v", err)
		}
	})

	t.Run("planted file", func(t *testing.T) {
		root := t.TempDir()
		mirrorForProbe(t, base, root)
		planted := filepath.Join(root, EvidenceRoot, "rust/fuzzingclient-run1/cases/verified_rust_ws_testee_us019_case_99_9.json")
		if err := os.WriteFile(planted, []byte("{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyEvidenceIntegrity(root); err == nil {
			t.Fatal("a file planted under the evidence root was accepted")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		root := t.TempDir()
		mirrorForProbe(t, base, root)
		if err := os.Remove(filepath.Join(root, casePath)); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyEvidenceIntegrity(root); err == nil {
			t.Fatal("a pinned file missing from the evidence root was accepted")
		}
	})
}

// The index binding and the behaviour-class cross-check must each be able to
// fail on their own. Each probe repairs every check ABOVE it, so the failure
// that follows can only come from the check under test.
func TestIndexBindingAndComparisonCrossCheckAreEachIsolated(t *testing.T) {
	base := repoRoot(t)
	casePath := filepath.Join(EvidenceRoot, "rust/fuzzingclient-run1/cases/verified_rust_ws_testee_us019_case_3_1.json")
	indexPath := filepath.Join(EvidenceRoot, "rust/fuzzingclient-run1/index.json")

	t.Run("index binding", func(t *testing.T) {
		root := t.TempDir()
		mirrorForProbe(t, base, root)
		// Change the case report's behaviour class and repair the digest
		// manifest, so integrity passes and only the index disagrees.
		mutateFile(t, root, casePath, `"behavior": "OK"`, `"behavior": "FAILED"`)
		repinManifest(t, root, casePath)
		if _, err := VerifyEvidenceIntegrity(root); err != nil {
			t.Fatalf("the repaired manifest must verify, or this probe proves nothing: %v", err)
		}
		err := runExpectingFailure(t, root)
		if !strings.Contains(err.Error(), "index behavior=") {
			t.Fatalf("expected the index binding to refuse, got: %v", err)
		}
	})

	t.Run("behaviour-class cross-check", func(t *testing.T) {
		root := t.TempDir()
		mirrorForProbe(t, base, root)
		mutateFile(t, root, casePath, `"behavior": "OK"`, `"behavior": "FAILED"`)
		repinManifest(t, root, casePath)
		// Repair the index too, so the index binding passes and only the
		// independently produced comparison document disagrees.
		mutateFile(t, root, indexPath, "\"3.1\": {\n         \"behavior\": \"OK\"", "\"3.1\": {\n         \"behavior\": \"FAILED\"")
		repinManifest(t, root, indexPath)
		if _, err := VerifyEvidenceIntegrity(root); err != nil {
			t.Fatalf("the repaired manifest must verify: %v", err)
		}
		err := runExpectingFailure(t, root)
		if !strings.Contains(err.Error(), "cross-check") {
			t.Fatalf("expected the behaviour-class cross-check to refuse, got: %v", err)
		}
	})
}

func runExpectingFailure(t *testing.T, root string) error {
	t.Helper()
	if _, err := Run(root); err != nil {
		return err
	}
	t.Fatal("the sweep accepted a tree this probe planted a defect in")
	return nil
}

// mirrorForProbe copies the inputs a probe needs into a scratch root: the
// evidence tree, its digest manifest, the ledger, the register and the
// committed sweep document. Probes mutate the copy; the committed tree is
// never written to.
func mirrorForProbe(t *testing.T, from, to string) {
	t.Helper()
	copyTree(t, filepath.Join(from, EvidenceRoot), filepath.Join(to, EvidenceRoot))
	for _, path := range []string{DigestManifestPath, LedgerPath, DocumentPath} {
		copyFile(t, filepath.Join(from, path), filepath.Join(to, path))
	}
}

func copyTree(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.Walk(from, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(from, path)
		if err != nil {
			return err
		}
		target := filepath.Join(to, relative)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mutateFile(t *testing.T, root, relative, from, to string) {
	t.Helper()
	path := filepath.Join(root, relative)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	replaced := strings.Replace(string(data), from, to, 1)
	if replaced == string(data) {
		t.Fatalf("probe found nothing to replace in %s", relative)
	}
	if err := os.WriteFile(path, []byte(replaced), 0o644); err != nil {
		t.Fatal(err)
	}
}

// repinManifest rewrites one entry of the digest manifest to match the file as
// the probe left it, so a later check is the one that fails.
func repinManifest(t *testing.T, root, relative string) {
	t.Helper()
	manifestPath := filepath.Join(root, DigestManifestPath)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	fileBytes, err := os.ReadFile(filepath.Join(root, relative))
	if err != nil {
		t.Fatal(err)
	}
	files, ok := manifest["files"].([]any)
	if !ok {
		t.Fatal("digest manifest has no files array")
	}
	target := filepath.ToSlash(relative)
	repinned := false
	for _, entry := range files {
		object, ok := entry.(map[string]any)
		if !ok || object["path"] != target {
			continue
		}
		object["sha256"] = "sha256:" + sha256Hex(fileBytes)
		object["bytes"] = float64(len(fileBytes))
		repinned = true
	}
	if !repinned {
		t.Fatalf("digest manifest does not pin %s", target)
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// The committed ledger-proposal drafts must recompute from the sweep. A draft
// whose measured extent has drifted from the reports is refused, which is what
// stops a proposal from quoting a number the run no longer supports.
func TestCommittedLedgerProposalDraftsAgreeWithTheSweep(t *testing.T) {
	root := repoRoot(t)
	_, document, err := Recompute(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyProposals(root, document); err != nil {
		t.Fatalf("ledger-proposal drafts: %v", err)
	}
	proposals, err := BuildProposals(document)
	if err != nil {
		t.Fatal(err)
	}
	if len(proposals) == 0 {
		t.Fatal("the sweep drafted no ledger proposals, so this check proved nothing")
	}
	// A draft is a proposal, not a record: the two position-dependent digests
	// must not carry plausible hex.
	for _, proposal := range proposals {
		if proposal.Record.PreviousDigest != PendingDigest || proposal.Record.RecordDigest != PendingDigest {
			t.Fatalf("draft for %s carries a chain digest a draft cannot know", proposal.SweepClassID)
		}
	}
}

// VerifyProposals must refuse an edited draft. Without this the draft check is
// only ever run against the bytes it just wrote.
func TestVerifyProposalsRefusesAnEditedDraft(t *testing.T) {
	source := repoRoot(t)
	root := t.TempDir()
	mirrorForProbe(t, source, root)
	for number := 1; ; number++ {
		from := ProposalPath(source, number)
		if _, err := os.Stat(from); err != nil {
			break
		}
		copyFile(t, from, ProposalPath(root, number))
	}
	_, document, err := Recompute(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyProposals(root, document); err != nil {
		t.Fatalf("the unmodified mirror must verify: %v", err)
	}
	path := ProposalPath(root, 1)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(data), `"server": 122`, `"server": 999`, 1)
	if edited == string(data) {
		t.Fatal("probe did not change the draft")
	}
	if err := os.WriteFile(path, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyProposals(root, document); err == nil {
		t.Fatal("a draft edited away from the sweep was accepted")
	}
}

// Every class the sweep names must be either drafted as a ledger proposal or
// already carried by a committed record. A class that is neither is a finding
// with no disposition, which is how findings quietly disappear.
func TestEveryClassIsEitherDraftedOrAlreadyLedgered(t *testing.T) {
	root := repoRoot(t)
	_, document, err := Recompute(root)
	if err != nil {
		t.Fatal(err)
	}
	drafted := map[string]bool{}
	proposals, err := BuildProposals(document)
	if err != nil {
		t.Fatal(err)
	}
	for _, proposal := range proposals {
		drafted[proposal.SweepClassID] = true
	}
	for _, class := range document.Classes {
		if drafted[class.ID] {
			continue
		}
		if class.ExistingLedgerSubjectRef != "" {
			continue
		}
		t.Fatalf("class %s has neither a drafted ledger proposal nor a committed ledger record", class.ID)
	}
}
