package lab

import (
	"archive/tar"
	"bytes"
	"strings"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

func pinnedRegistrySource() []byte {
	return []byte(strings.Join([]string{
		"Case1_1", "Case2_1", "Case3_1", "Case4_1", "Case5_1", "Case6_X_X", "Case7_1",
		"Case9_1", "Case10_1", "Case12_1", "Case13_1",
	}, "\n"))
}

func TestStaticAutobahnGeneratorParsersDeriveNumericIdentities(t *testing.T) {
	groups := strings.Repeat("   vs = [\"group\", []]\n   vs[1].append((True, 'x'))\n   UTF8_TEST_SEQUENCES.append(vs)\n", 19)
	case6 := "def createUtf8TestSequences():\n" + groups + "   return UTF8_TEST_SEQUENCES\n\nCase6_X_X = []\ndef marker():\n   C = type(\"Case6_%d_%d\" % (i, j), (), {})\ni = 5\nfor t in createUtf8TestSequences():\n   pass\n"
	ids, err := deriveAutobahnGeneratorIDs("Case6_X_X", []byte(case6))
	if err != nil || len(ids) != 19 || ids[0] != "6.5.1" || ids[len(ids)-1] != "6.23.1" {
		t.Fatalf("Case6 ids=%v err=%v", ids, err)
	}
	case7 := "tests = [1000,1001,1002]\nCase7_7_X = []\nfor s in tests:\n   C = type(\"Case7_7_%d\" % i, (), {})\n"
	ids, err = deriveAutobahnGeneratorIDs("Case7_7_X", []byte(case7))
	if err != nil || !equalStrings(ids, []string{"7.7.1", "7.7.2", "7.7.3"}) {
		t.Fatalf("Case7 ids=%v err=%v", ids, err)
	}
	case9 := "tests = [(0, 1000, 60),(16, 1000, 60)]\nfor b in [False, True]:\n   cc = \"Case9_7_%d\"\n   cc = \"Case9_8_%d\"\n"
	ids, err = deriveAutobahnGeneratorIDs("Case9_8_X", []byte(case9))
	if err != nil || !equalStrings(ids, []string{"9.8.1", "9.8.2"}) {
		t.Fatalf("Case9 ids=%v err=%v", ids, err)
	}
	case12 := "MSG_SIZES = [(16,1,1,0),(64,1,1,0)]\nWS_COMPRESSION_TESTDATA_KEYS = ['a','b']\nDEFLATE_PARAMS = [(a, [b]),(c, [d]),(e, [f])]\ncc = \"Case12_%d_%d\" % (j, i)\ncc = \"Case13_%d_%d\" % (j, i)\n"
	ids, err = deriveAutobahnGeneratorIDs("Case12_X_X", []byte(case12))
	if err != nil || len(ids) != 4 || ids[3] != "12.2.2" {
		t.Fatalf("Case12 ids=%v err=%v", ids, err)
	}
	ids, err = deriveAutobahnGeneratorIDs("Case13_X_X", []byte(case12))
	if err != nil || len(ids) != 6 || ids[5] != "13.3.2" {
		t.Fatalf("Case13 ids=%v err=%v", ids, err)
	}
	_, err = deriveAutobahnGeneratorIDs("Case7_7_X", []byte(strings.ReplaceAll(case7, `Case7_7_%d`, `Case7_8_%d`)))
	assertFinding(t, err, "INVALID_AUTOBAHN_EXPANSION")
}

func TestAutobahnArchiveDataValidationRejectsLinksDuplicatesAndDrift(t *testing.T) {
	root := "pinned-root"
	memberPath := root + "/case/case7_7_X.py"
	source := []byte("tests = [1000]\n")
	required := map[string]string{memberPath: intake.DigestBytes(source)}
	valid := autobahnTarFixture(t, []tar.Header{{Name: memberPath, Mode: 0o644, Size: int64(len(source)), Typeflag: tar.TypeReg}}, [][]byte{source})
	members, err := validateAndReadAutobahnTar(valid, root, required)
	if err != nil || !bytes.Equal(members[memberPath], source) {
		t.Fatalf("members=%v err=%v", members, err)
	}
	link := autobahnTarFixture(t, []tar.Header{{Name: memberPath, Linkname: "target", Typeflag: tar.TypeSymlink}}, [][]byte{nil})
	assertFinding(t, func() error { _, err := validateAndReadAutobahnTar(link, root, required); return err }(), "UNSAFE_ARCHIVE_ENTRY")
	duplicate := autobahnTarFixture(t, []tar.Header{{Name: memberPath, Mode: 0o644, Size: int64(len(source)), Typeflag: tar.TypeReg}, {Name: memberPath, Mode: 0o644, Size: int64(len(source)), Typeflag: tar.TypeReg}}, [][]byte{source, source})
	assertFinding(t, func() error { _, err := validateAndReadAutobahnTar(duplicate, root, required); return err }(), "DUPLICATE_ARCHIVE_ENTRY")
	wrongRoot := autobahnTarFixture(t, []tar.Header{{Name: "other/case.py", Mode: 0o644, Size: int64(len(source)), Typeflag: tar.TypeReg}}, [][]byte{source})
	assertFinding(t, func() error { _, err := validateAndReadAutobahnTar(wrongRoot, root, required); return err }(), "UNKNOWN_AUTOBAHN_ARCHIVE_STRUCTURE")
	mutatedRequired := map[string]string{memberPath: intake.DigestBytes([]byte("mutated"))}
	assertFinding(t, func() error { _, err := validateAndReadAutobahnTar(valid, root, mutatedRequired); return err }(), "AUTOBAHN_MEMBER_DIGEST_MISMATCH")
}

func TestPinnedReportSemanticsRequireOneCaseFlushAndExactFilenames(t *testing.T) {
	source := strings.Join([]string{
		`elif self.path == "/updateReports":`, `self.factory.createReports()`, `report_filename = "index.json"`,
		`report_filename = "index.html"`, `return self.cleanForFilename(agentId) + "_case_" + c + "." + ext`,
		"self.createReports()\n            reactor.stop()",
	}, "\n")
	if err := verifyAutobahnReportSemantics(source); err != nil {
		t.Fatal(err)
	}
	if err := verifyAutobahnReportSemantics(strings.ReplaceAll(source, "\n", "\r\n")); err != nil {
		t.Fatalf("accepted CRLF source: %v", err)
	}
	for _, removed := range []string{"/updateReports", "index.json", "index.html", "_case_", "reactor.stop()"} {
		mutated := strings.Replace(source, removed, "mutated", 1)
		assertFinding(t, verifyAutobahnReportSemantics(mutated), "AUTOBAHN_REPORT_CONTRACT_UNRESOLVED")
	}
}

func autobahnTarFixture(t *testing.T, headers []tar.Header, contents [][]byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for index := range headers {
		header := headers[index]
		if err := writer.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if len(contents[index]) != 0 {
			if _, err := writer.Write(contents[index]); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func parsedRegistry(t *testing.T) AutobahnRegistry {
	t.Helper()
	raw := pinnedRegistrySource()
	member := pinnedAutobahnGeneratorMembers["Case6_X_X"]
	registry, err := ParsePinnedAutobahnRegistry(raw, intake.DigestBytes(raw), map[string]RegistryExpansion{
		"Case6_X_X": {ArchiveDigest: PinnedAutobahnSourceArchiveDigest, MemberPath: member.path, SourceDigest: member.digest, CaseIDs: []string{"6.1.1", "6.1.2"}, sourceValidated: true, caseIDsDigest: digestStringSlice([]string{"6.1.1", "6.1.2"})},
	})
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func TestStaticAutobahnRegistrySelectionAndExactReconciliation(t *testing.T) {
	registry := parsedRegistry(t)
	selection, err := SelectAutobahnRegistry(registry)
	if err != nil {
		t.Fatal(err)
	}
	if len(selection.SelectedCaseIDs) != 9 || len(selection.ExcludedCaseIDs) != 3 {
		t.Fatalf("selection = %+v", selection)
	}
	results := make([]AutobahnResult, len(selection.SelectedCaseIDs))
	for index, id := range selection.SelectedCaseIDs {
		results[index] = AutobahnResult{CaseID: id, Status: "OK", ResultDigest: intake.DigestBytes([]byte("result:" + id)), ObservationDigest: intake.DigestBytes([]byte("observation:" + id))}
	}
	for _, mode := range []string{"client", "server"} {
		for index := range results {
			results[index].BindingDigest, err = AutobahnResultBindingDigest(mode, results[index])
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := ReconcileAutobahn(registry, selection, mode, results); err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
	}
	mutated := append([]AutobahnResult(nil), results[:len(results)-1]...)
	assertFinding(t, ReconcileAutobahn(registry, selection, "client", mutated), "AUTOBAHN_RESULT_MISMATCH")
	mutated = append([]AutobahnResult(nil), results...)
	mutated[0].CaseID = selection.ExcludedCaseIDs[0]
	assertFinding(t, ReconcileAutobahn(registry, selection, "server", mutated), "AUTOBAHN_RESULT_MISMATCH")
}

func TestAutobahnResultsRejectNonterminalAndDigestMutations(t *testing.T) {
	registry := parsedRegistry(t)
	selection, err := SelectAutobahnRegistry(registry)
	if err != nil {
		t.Fatal(err)
	}
	results := make([]AutobahnResult, len(selection.SelectedCaseIDs))
	for index, id := range selection.SelectedCaseIDs {
		results[index] = AutobahnResult{CaseID: id, Status: "OK", ResultDigest: intake.DigestBytes([]byte("result:" + id)), ObservationDigest: intake.DigestBytes([]byte("observation:" + id))}
		results[index].BindingDigest, err = AutobahnResultBindingDigest("client", results[index])
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, status := range []string{"NOT_RUN", "SKIPPED", "MISSING", "PASS", "candidate-status"} {
		mutated := append([]AutobahnResult(nil), results...)
		mutated[0].Status = status
		assertFinding(t, ReconcileAutobahn(registry, selection, "client", mutated), "NONTERMINAL_AUTOBAHN_STATUS")
	}
	for name, mutate := range map[string]func(*AutobahnResult){
		"result": func(result *AutobahnResult) { result.ResultDigest = intake.DigestBytes([]byte("changed-result")) },
		"observation": func(result *AutobahnResult) {
			result.ObservationDigest = intake.DigestBytes([]byte("changed-observation"))
		},
		"binding": func(result *AutobahnResult) { result.BindingDigest = intake.DigestBytes([]byte("changed-binding")) },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := append([]AutobahnResult(nil), results...)
			mutate(&mutated[0])
			assertFinding(t, ReconcileAutobahn(registry, selection, "client", mutated), "AUTOBAHN_RESULT_BINDING_MISMATCH")
		})
	}
}

func TestStaticAutobahnParserFailsClosedOnGeneratorsAndSourceDrift(t *testing.T) {
	raw := pinnedRegistrySource()
	_, err := ParsePinnedAutobahnRegistry(raw, intake.DigestBytes(raw), nil)
	assertFinding(t, err, "UNRESOLVED_AUTOBAHN_GENERATOR")
	_, err = ParsePinnedAutobahnRegistry(raw, intake.DigestBytes([]byte("different")), nil)
	assertFinding(t, err, "INVALID_AUTOBAHN_REGISTRY_SOURCE")
	_, err = ParsePinnedAutobahnRegistry(raw, intake.DigestBytes(raw), map[string]RegistryExpansion{
		"Case6_X_X": {ArchiveDigest: PinnedAutobahnSourceArchiveDigest, MemberPath: "wrong", SourceDigest: intake.DigestBytes([]byte("Case7_1_1")), CaseIDs: []string{"7.1.1"}},
	})
	assertFinding(t, err, "INVALID_AUTOBAHN_EXPANSION")
	registry := AutobahnRegistry{SchemaVersion: "1.0.0", SourceDigest: intake.DigestBytes(raw), CaseIDs: parsedRegistry(t).CaseIDs}
	assertFinding(t, func() error { _, err := SelectAutobahnRegistry(registry); return err }(), "AUTOBAHN_REGISTRY_PROVENANCE_REQUIRED")
	registry = parsedRegistry(t)
	registry.CaseIDs[0] = "1.999"
	assertFinding(t, func() error { _, err := SelectAutobahnRegistry(registry); return err }(), "AUTOBAHN_REGISTRY_PROVENANCE_REQUIRED")
}
