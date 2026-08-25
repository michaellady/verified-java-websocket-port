package securitygate

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestUS007Acceptance_PoliciesCatalogAndOwnerCeiling(t *testing.T) {
	verdict, err := Verify(context.Background(), Request{RootPath: repoRoot(t), Operation: OperationVerify})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verdict.State != "BLOCKED_SANDBOX_ENFORCEMENT_UNAVAILABLE" {
		t.Fatalf("state = %q", verdict.State)
	}
	if len(verdict.Findings) != 1 || verdict.Findings[0].Code != "SANDBOX_ENFORCEMENT_UNAVAILABLE" || verdict.Findings[0].Disposition != "BLOCK" {
		t.Fatalf("findings = %#v", verdict.Findings)
	}
	if verdict.Assurance != "OWNER_ATTESTED_NOT_INDEPENDENT" || verdict.IndependentReviewClaimed || verdict.PublicationAuthorized {
		t.Fatalf("owner-only boundary widened: %#v", verdict)
	}
	if verdict.SecurityEvidenceRoot == "" {
		t.Fatal("security evidence root is empty")
	}
}

func TestUS007E2E_InertAttackMatrix(t *testing.T) {
	cases := map[string]struct{ code, disposition string }{
		"good-benign-ingest":       {"", ""},
		"static-exec-request":      {"STATIC_EXECUTION_FORBIDDEN", "QUARANTINE"},
		"path-traversal":           {"PATH_TRAVERSAL", "QUARANTINE"},
		"absolute-path":            {"ABSOLUTE_PATH", "QUARANTINE"},
		"symlink":                  {"UNSAFE_SYMLINK", "QUARANTINE"},
		"hard-link":                {"HARD_LINK_DENIED", "QUARANTINE"},
		"special-file":             {"SPECIAL_FILE_DENIED", "QUARANTINE"},
		"archive-bomb":             {"ARCHIVE_LIMIT_EXCEEDED", "QUARANTINE"},
		"nested-archive":           {"NESTED_ARCHIVE_DENIED", "QUARANTINE"},
		"case-collision":           {"NORMALIZATION_COLLISION", "QUARANTINE"},
		"unicode-collision":        {"NORMALIZATION_COLLISION", "QUARANTINE"},
		"quota-breach":             {"QUOTA_EXCEEDED", "QUARANTINE"},
		"partial-promotion":        {"PARTIAL_PROMOTION", "QUARANTINE"},
		"digest-mismatch":          {"DIGEST_MISMATCH", "QUARANTINE"},
		"dangling-provenance":      {"DANGLING_PROVENANCE", "QUARANTINE"},
		"cross-company-provenance": {"CROSS_COMPANY_REFERENCE", "QUARANTINE"},
		"maven-plugin":             {"UNPROMOTED_EXECUTABLE", "QUARANTINE"},
		"annotation-processor":     {"UNPROMOTED_EXECUTABLE", "QUARANTINE"},
		"rust-build-script":        {"UNPROMOTED_EXECUTABLE", "QUARANTINE"},
		"proc-macro":               {"UNPROMOTED_EXECUTABLE", "QUARANTINE"},
		"language-server-import":   {"UNPROMOTED_EXECUTABLE", "QUARANTINE"},
		"autobahn-python":          {"UNPROMOTED_EXECUTABLE", "QUARANTINE"},
		"container-entrypoint":     {"UNPROMOTED_EXECUTABLE", "QUARANTINE"},
		"autobahn-third-run":       {"AUTOBAHN_RERUN_FORBIDDEN", "BLOCK"},
		"receipt-mutation":         {"CANONICAL_EVIDENCE_MUTATION", "REVOKE"},
		"network-probe":            {"NETWORK_POLICY_VIOLATION", "QUARANTINE"},
		"secret-probe":             {"SECRET_ACCESS_DENIED", "QUARANTINE"},
		"protected-store-probe":    {"FORBIDDEN_MOUNT_EXPOSED", "REVOKE"},
		"cpu-bomb":                 {"RESOURCE_TERMINATION_MISSING", "QUARANTINE"},
		"disk-bomb":                {"RESOURCE_TERMINATION_MISSING", "QUARANTINE"},
		"fd-bomb":                  {"RESOURCE_TERMINATION_MISSING", "QUARANTINE"},
		"good-sandbox-canaries":    {"", ""},
		"memory-bomb":              {"RESOURCE_TERMINATION_MISSING", "QUARANTINE"},
		"output-bomb":              {"RESOURCE_TERMINATION_MISSING", "QUARANTINE"},
		"pid-bomb":                 {"RESOURCE_TERMINATION_MISSING", "QUARANTINE"},
		"wall-bomb":                {"RESOURCE_TERMINATION_MISSING", "QUARANTINE"},
		"cleanup-residue":          {"SANDBOX_CLEANUP_INCOMPLETE", "REVOKE"},
		"capture-failure":          {"ARTIFACT_CAPTURE_INCOMPLETE", "QUARANTINE"},
		"good-safe-projection":     {"", ""},
		"protected-leak":           {"PROTECTED_PUBLICATION_DISCLOSURE", "REVOKE"},
		"expected-output-leak":     {"EXPECTED_OUTPUT_DISCLOSURE", "REVOKE"},
		"raw-diagnostic-leak":      {"RAW_DIAGNOSTIC_DISCLOSURE", "REVOKE"},
		"identifier-leak":          {"IDENTIFIER_DISCLOSURE", "REVOKE"},
		"credential-leak":          {"CREDENTIAL_DISCLOSURE", "REVOKE"},
		"cache-leak":               {"CACHE_DISCLOSURE", "REVOKE"},
		"provenance-gap":           {"PUBLIC_PROVENANCE_GAP", "BLOCK"},
		"unclassified-descendant":  {"PUBLIC_DESCENDANT_UNCLASSIFIED", "BLOCK"},
		"late-public-mutation":     {"PUBLIC_PROJECTION_DRIFT", "REVOKE"},
		"independence-claim":       {"ASSURANCE_CEILING_EXCEEDED", "REVOKE"},
		"publication-attempt":      {"PUBLICATION_NOT_AUTHORIZED", "BLOCK"},
	}
	for id, want := range cases {
		t.Run(id, func(t *testing.T) {
			verdict, err := Verify(context.Background(), Request{RootPath: repoRoot(t), Operation: OperationVerify, FixtureID: id})
			if err != nil {
				t.Fatalf("verify fixture: %v", err)
			}
			if want.code == "" {
				if len(verdict.Findings) != 0 {
					t.Fatalf("findings = %#v", verdict.Findings)
				}
				return
			}
			if len(verdict.Findings) != 1 || verdict.Findings[0].Code != want.code || verdict.Findings[0].Disposition != want.disposition {
				t.Fatalf("findings = %#v, want %s/%s", verdict.Findings, want.code, want.disposition)
			}
		})
	}
}

func TestUS007Acceptance_RootSnapshotRejectsLinks(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "sentinel.txt"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("sentinel.txt", filepath.Join(root, "linked.txt")); err != nil {
		t.Fatal(err)
	}
	verdict, err := Ingest(context.Background(), Request{RootPath: repoRoot(t), Operation: OperationIngest, CandidateRoot: root, StorePath: t.TempDir()})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(verdict.Findings) != 1 || verdict.Findings[0].Code != "UNSAFE_SYMLINK" {
		t.Fatalf("findings = %#v", verdict.Findings)
	}
}

func TestUS007E2E_ControlledCanaries(t *testing.T) {
	_, err := RunControlledCanary(context.Background(), CanaryRequest{RootPath: repoRoot(t), CanaryID: "CLEAN_EXIT", PlanDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	if err == nil || err.Error() != "SANDBOX_ENFORCEMENT_UNAVAILABLE/BLOCK" {
		t.Fatalf("err = %v, want typed fail-closed enforcement result", err)
	}
	t.Skip("SANDBOX_ENFORCEMENT_UNAVAILABLE/BLOCK: no ordinary host-process substitute is allowed")
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}
