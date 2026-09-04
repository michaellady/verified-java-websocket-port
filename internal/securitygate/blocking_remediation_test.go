package securitygate

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
	"github.com/michaellady/verified-java-websocket-port/internal/lab"
)

func TestUS007Acceptance_AcceptedRootEnforcesIngestionQuotasBeforePromotion(t *testing.T) {
	store := t.TempDir()
	objects := []intake.Object{
		{ID: "a.txt", Digest: intake.DigestBytes([]byte("aaaaa")), Bytes: []byte("aaaaa")},
		{ID: "b.txt", Digest: intake.DigestBytes([]byte("bbbbb")), Bytes: []byte("bbbbb")},
	}
	rootDigest, err := intake.PromoteDirectory(store, objects)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := lab.LoadAcceptedRoot(store, rootDigest)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := loadPolicies(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.root.Close()

	tests := []struct {
		name   string
		mutate func(*quotaPolicy)
	}{
		{"object count", func(q *quotaPolicy) { q.MaxFiles = 1 }},
		{"single object bytes", func(q *quotaPolicy) { q.MaxFileBytes = 4 }},
		{"total object bytes", func(q *quotaPolicy) { q.MaxTotalBytes = 9 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := snapshot.ingestion
			test.mutate(&policy.Quotas)
			manifest, copied, finding := snapshotAcceptedRoot(rootDigest, accepted, policy)
			if finding == nil || finding.Code != "QUOTA_EXCEEDED" || finding.Disposition != "QUARANTINE" {
				t.Fatalf("finding=%#v", finding)
			}
			if len(manifest.Files) != 0 || len(copied) != 0 {
				t.Fatalf("quota failure copied/promoted data: manifest=%#v copied=%#v", manifest, copied)
			}
		})
	}
}

func TestUS007Acceptance_AuthoritativeIngestRejectsMutablePathAndUsesExplicitFixtureSeam(t *testing.T) {
	candidate := t.TempDir()
	if err := os.WriteFile(filepath.Join(candidate, "safe.txt"), []byte("inert"), 0o600); err != nil {
		t.Fatal(err)
	}

	authoritative, err := Ingest(context.Background(), Request{
		RootPath:      repoRoot(t),
		Operation:     OperationIngest,
		CandidateRoot: candidate,
		StorePath:     t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(authoritative.Findings) != 1 || authoritative.Findings[0].Code != "PROMOTION_BINDING_MISMATCH" {
		t.Fatalf("mutable authoritative source verdict=%#v", authoritative)
	}

	fixture, err := Ingest(context.Background(), Request{
		RootPath:          repoRoot(t),
		Operation:         OperationIngest,
		StorePath:         t.TempDir(),
		fixtureSourcePath: candidate,
	})
	if err != nil {
		t.Fatal(err)
	}
	if fixture.State != "PASS_SYNTHETIC_NON_CLAIM" || fixture.QuarantineRoot == "" || len(fixture.Findings) != 0 {
		t.Fatalf("fixture verdict=%#v", fixture)
	}
}

func TestUS007Acceptance_ExternalSandboxReceiptCannotAuthenticateItself(t *testing.T) {
	root := copySecurityInputs(t)
	snapshot, err := loadPolicies(root)
	if err != nil {
		t.Fatal(err)
	}
	plan, receipt := inertSandboxPair(snapshot, "CLEAN_EXIT")
	snapshot.root.Close()
	write := func(name string, value any) {
		data, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if writeErr := os.WriteFile(filepath.Join(root, name), data, 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	write("plan.json", plan)
	write("receipt.json", receipt)

	verdict, err := VerifySandbox(context.Background(), Request{
		RootPath: root, Operation: OperationVerifySandbox,
		PlanPath: "plan.json", ReceiptPath: "receipt.json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(verdict.Findings) != 1 || verdict.Findings[0].Code != "SANDBOX_ENFORCEMENT_UNAVAILABLE" || verdict.Findings[0].Disposition != "BLOCK" {
		t.Fatalf("external receipt verdict=%#v", verdict)
	}
}

func TestUS007Acceptance_StaticInventoryIsExhaustivePerRetainedMember(t *testing.T) {
	cases := []struct {
		name  string
		path  string
		input string
		media string
		want  []string
	}{
		{"maven", "pom.xml", `<project><parent/><dependencyManagement/><dependency/><pluginManagement/><plugin><extensions>true</extensions><annotationProcessorPaths/><arg>-processor</arg></plugin></project>`, "REGULAR", []string{"JVM_DEPENDENCY", "MAVEN_ANNOTATION_PROCESSOR", "MAVEN_CORE", "MAVEN_EXTENSION", "MAVEN_PLUGIN"}},
		{"rust manifest", "Cargo.toml", "[package]\nbuild = \"build.rs\"\n[lib]\nproc-macro = true\n[dependencies]\na = \"=1\"", "REGULAR", []string{"CARGO_BUILD_SCRIPT", "RUST_DEPENDENCY", "RUST_PROC_MACRO"}},
		{"rust config", ".cargo/config.toml", "runner = \"inert\"\nrustc-wrapper = \"inert\"\nlinker = \"inert\"", "REGULAR", []string{"CARGO_RUNNER_OR_WRAPPER"}},
		{"language servers", "lsp-plugins.json", `{"jdt.ls":{},"rust-analyzer":{},"glancer":{},"language-server":"inert"}`, "REGULAR", []string{"GLANCER_IMPORT", "JDT_LS_IMPORT", "LANGUAGE_SERVER_PLUGIN", "RUST_ANALYZER_IMPORT"}},
		{"autobahn", "autobahn/requirements.txt", "autobahn-testsuite==0.8\npython3 wstest", "REGULAR", []string{"AUTOBAHN_PYTHON_DISTRIBUTION", "AUTOBAHN_PYTHON_RUNTIME", "AUTOBAHN_SCRIPT"}},
		{"OCI", "oci/config.json", `{"architecture":"amd64","Entrypoint":["inert"],"Cmd":["inert"],"layers":["oci.image.layer"],"runtime helper":"runc"}`, "REGULAR", []string{"CONTAINER_COMMAND", "CONTAINER_ENTRYPOINT", "CONTAINER_LAYER", "CONTAINER_RUNTIME_HELPER"}},
		{"archive", "inert.zip", "PK\x03\x04", "ZIP", []string{"ARCHIVE_DECODER"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			items := discoverExecutables(tc.path, []byte(tc.input), 0o600, tc.media)
			got := make([]string, len(items))
			for i := range items {
				got[i] = items[i].Class
				if items[i].PromotionReceipt != "" || len(items[i].AllowedOperations) != 0 {
					t.Fatalf("candidate metadata created a promotion/use binding: %#v", items[i])
				}
			}
			sort.Strings(got)
			if len(got) != len(tc.want) {
				t.Fatalf("classes=%v want=%v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("classes=%v want=%v", got, tc.want)
				}
			}
		})
	}
}

func TestUS007Acceptance_RootSetRejectsSymlinkLaundering(t *testing.T) {
	candidate := t.TempDir()
	if err := os.WriteFile(filepath.Join(candidate, "safe.txt"), []byte("inert"), 0o600); err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	storeLink := filepath.Join(parent, "store-link")
	if err := os.Symlink(t.TempDir(), storeLink); err != nil {
		t.Fatal(err)
	}
	verdict, err := Ingest(context.Background(), Request{
		RootPath: repoRoot(t), Operation: OperationIngest,
		StorePath: storeLink, fixtureSourcePath: candidate,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(verdict.Findings) != 1 || verdict.Findings[0].Code != "ROOT_CONFINEMENT_FAILED" {
		t.Fatalf("symlink store verdict=%#v", verdict)
	}

	rootLink := filepath.Join(parent, "root-link")
	if err := os.Symlink(repoRoot(t), rootLink); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), Request{RootPath: rootLink, Operation: OperationVerify}); err == nil || !strings.Contains(err.Error(), "ROOT_CONFINEMENT_FAILED") {
		t.Fatalf("symlink project root err=%v", err)
	}
}

func TestUS007Acceptance_SnapshotRevalidatesCompleteDirectorySet(t *testing.T) {
	candidate := t.TempDir()
	if err := os.Mkdir(filepath.Join(candidate, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(candidate, "nested", "before.txt"), []byte("inert"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := snapshotRevalidationHook
	t.Cleanup(func() { snapshotRevalidationHook = previous })
	snapshotRevalidationHook = func() {
		if err := os.WriteFile(filepath.Join(candidate, "nested", "late.txt"), []byte("late inert bytes"), 0o600); err != nil {
			t.Error(err)
		}
	}

	policySnapshot, err := loadPolicies(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer policySnapshot.root.Close()
	_, _, finding := snapshotCandidate(candidate, policySnapshot.ingestion)
	if finding == nil || finding.Code != "IMMUTABLE_SNAPSHOT_FAILED" {
		t.Fatalf("finding=%#v", finding)
	}
}

func TestUS007Acceptance_ProjectionLoadsRecursesAndScansExactAcceptedRoot(t *testing.T) {
	root := repoRoot(t)
	goodStore, goodRoot := acceptedProjectionFixture(t, "public/readme.txt", []byte("inert public bytes"), "PUBLIC", true)
	good, err := Project(context.Background(), Request{
		RootPath: root, Operation: OperationProject,
		CandidateRoot: goodRoot, StorePath: goodStore,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(good.Findings) != 1 || good.Findings[0].Code != "PROTECTED_CLASSIFIER_UNAVAILABLE" || !isSHA256Digest(good.ProjectionRoot) {
		t.Fatalf("good real projection verdict=%#v", good)
	}
	if _, err := lab.LoadAcceptedRoot(goodStore, good.ProjectionRoot); err != nil {
		t.Fatalf("retained projection root did not reopen: %v", err)
	}

	leakStore, leakRoot := acceptedProjectionFixture(t, "public/readme.txt", []byte("SYNTHETIC_TOKEN_VALUE"), "PUBLIC", true)
	leak, err := Project(context.Background(), Request{
		RootPath: root, Operation: OperationProject,
		CandidateRoot: leakRoot, StorePath: leakStore,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(leak.Findings) != 1 || leak.Findings[0].Code != "CREDENTIAL_DISCLOSURE" || leak.ProjectionRoot != "" {
		t.Fatalf("leak projection verdict=%#v", leak)
	}

	unclassifiedStore, unclassifiedRoot := acceptedProjectionFixture(t, "public/readme.txt", []byte("inert"), "", true)
	unclassified, err := Project(context.Background(), Request{
		RootPath: root, Operation: OperationProject,
		CandidateRoot: unclassifiedRoot, StorePath: unclassifiedStore,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(unclassified.Findings) != 1 || unclassified.Findings[0].Code != "PUBLIC_DESCENDANT_UNCLASSIFIED" {
		t.Fatalf("unclassified projection verdict=%#v", unclassified)
	}
}

func TestUS007Acceptance_ReleaseFixtureBindsObservedProjectionResult(t *testing.T) {
	tests := []struct {
		fixture string
		content string
		code    string
	}{
		{"cache-leak", "SYNTHETIC_CACHE_STATE", "CACHE_DISCLOSURE"},
		{"credential-leak", "SYNTHETIC_TOKEN_VALUE", "CREDENTIAL_DISCLOSURE"},
		{"expected-output-leak", "SYNTHETIC_GOLDEN_ANSWER", "EXPECTED_OUTPUT_DISCLOSURE"},
		{"identifier-leak", "SYNTHETIC_SESSION_IDENTIFIER", "IDENTIFIER_DISCLOSURE"},
		{"protected-leak", "SYNTHETIC_PROTECTED_CANARY", "PROTECTED_PUBLICATION_DISCLOSURE"},
		{"raw-diagnostic-leak", "SYNTHETIC_RAW_TRACE", "RAW_DIAGNOSTIC_DISCLOSURE"},
	}
	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			store, candidateRoot := acceptedProjectionFixture(t, "public/readme.txt", []byte(test.content), "PUBLIC", true)
			before := acceptedRootCount(t, store)
			verdict, err := Project(context.Background(), Request{
				RootPath: repoRoot(t), Operation: OperationProject, CandidateRoot: candidateRoot,
				FixtureID: test.fixture, StorePath: store,
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(verdict.Findings) != 1 || verdict.Findings[0].Code != test.code || verdict.Findings[0].Disposition != "REVOKE" || verdict.ProjectionRoot != "" || verdict.PublicationAuthorized {
				t.Fatalf("verdict=%#v", verdict)
			}
			if after := acceptedRootCount(t, store); after != before {
				t.Fatalf("rejected projection became durable: accepted roots before=%d after=%d", before, after)
			}
		})
	}

	store, candidateRoot := acceptedProjectionFixture(t, "public/readme.txt", []byte("unrelated inert safe bytes"), "PUBLIC", true)
	before := acceptedRootCount(t, store)
	verdict, err := Project(context.Background(), Request{
		RootPath: repoRoot(t), Operation: OperationProject, CandidateRoot: candidateRoot,
		FixtureID: "credential-leak", StorePath: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(verdict.Findings) != 1 || verdict.Findings[0].Code != "INVALID_SECURITY_POLICY" || verdict.Findings[0].Disposition != "BLOCK" || verdict.ProjectionRoot != "" || verdict.PublicationAuthorized {
		t.Fatalf("unbound fixture verdict=%#v", verdict)
	}
	if after := acceptedRootCount(t, store); after != before {
		t.Fatalf("unbound fixture projection became durable: accepted roots before=%d after=%d", before, after)
	}
}

func TestUS007Acceptance_IncludedDirectoryRequiresRecursivelyIncludedAncestor(t *testing.T) {
	provenance := "scope:SYNTHETIC_NON_CLAIM/company:" + requiredCompany + "/project:" + requiredProject
	manifest := candidateManifest{
		SchemaVersion: "1.0.0", Classification: "QUARANTINED",
		Directories: []candidateDirectory{
			{Path: "internal", CollisionKey: "internal", Classification: "INTERNAL", Provenance: provenance},
			{Path: "internal/public", CollisionKey: "internal/public", Classification: "PUBLIC", Provenance: provenance},
		},
		Files: []candidateFile{}, HostileExecutables: []hostileExecutable{},
	}
	manifestBytes, err := intake.CanonicalJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	store := t.TempDir()
	rootDigest, err := intake.PromoteDirectory(store, []intake.Object{{ID: "candidate-manifest", Digest: intake.DigestBytes(manifestBytes), Bytes: manifestBytes}})
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := Project(context.Background(), Request{
		RootPath: repoRoot(t), Operation: OperationProject, CandidateRoot: rootDigest, StorePath: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(verdict.Findings) != 1 || verdict.Findings[0].Code != "PUBLIC_DESCENDANT_UNCLASSIFIED" || verdict.Findings[0].Disposition != "BLOCK" {
		t.Fatalf("verdict=%#v", verdict)
	}
}

func TestUS007Acceptance_AutobahnClosureUsesLabAdapterAndExactAttemptPins(t *testing.T) {
	root := copySecurityInputs(t)
	path := filepath.Join(root, "evidence", "java", "autobahn-baseline.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	mutated := strings.Replace(string(data),
		"sha256:ca942585442eb4be74a62533fa2b44a985970612ce6f69d5c13df8ede83c6cff",
		"sha256:"+strings.Repeat("1", 64), 1)
	if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPolicies(root); err == nil || !strings.Contains(err.Error(), "CANONICAL_EVIDENCE_MUTATION") {
		t.Fatalf("mutated Autobahn closure err=%v", err)
	}
}

func TestUS007Acceptance_FixtureEvidenceRetainsObservedComponentOutputs(t *testing.T) {
	snapshot, err := loadPolicies(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.root.Close()
	for _, item := range snapshot.catalog.Cases {
		observation, err := evaluateFixture(snapshot, item)
		if err != nil {
			t.Fatalf("fixture %s: %v", item.ID, err)
		}
		if observation.Component == "" || !isSHA256Digest(observation.InputDigest) || !isSHA256Digest(observation.OutputDigest) || observation.State == "" {
			t.Fatalf("fixture %s incomplete observation=%#v", item.ID, observation)
		}
		if item.ID == "good-sandbox-canaries" {
			if observation.Code != "PROTECTED_CALLER_REQUIRED" || observation.Disposition != "BLOCK" || observation.Exit != 1 {
				t.Fatalf("candidate canary launch observation=%#v", observation)
			}
			continue
		}
		if observation.Code != item.ExpectedCode || observation.Disposition != item.ExpectedDisposition {
			t.Fatalf("fixture %s observation=%#v expected=%s/%s", item.ID, observation, item.ExpectedCode, item.ExpectedDisposition)
		}
	}
}

func acceptedProjectionFixture(t *testing.T, path string, content []byte, classification string, includeParent bool) (string, string) {
	t.Helper()
	digest := intake.DigestBytes(content)
	directories := []candidateDirectory{}
	if includeParent {
		directories = append(directories, candidateDirectory{
			Path: "public", CollisionKey: "public", Classification: "PUBLIC",
			Provenance: "scope:SYNTHETIC_NON_CLAIM/company:" + requiredCompany + "/project:" + requiredProject,
		})
	}
	manifest := candidateManifest{
		SchemaVersion: "1.0.0", Classification: "QUARANTINED",
		Directories: directories,
		Files: []candidateFile{{
			Path: path, CollisionKey: collisionKey(path), ObjectID: "blob." + strings.TrimPrefix(digest, "sha256:"),
			Digest: digest, ByteSize: int64(len(content)), MediaKind: "REGULAR", Classification: classification,
			Provenance: "scope:SYNTHETIC_NON_CLAIM/company:" + requiredCompany + "/project:" + requiredProject + "/source:" + digest,
		}},
		HostileExecutables: []hostileExecutable{},
	}
	manifestBytes, err := intake.CanonicalJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	store := t.TempDir()
	acceptedRoot, err := intake.PromoteDirectory(store, []intake.Object{
		{ID: "candidate-manifest", Digest: intake.DigestBytes(manifestBytes), Bytes: manifestBytes},
		{ID: "blob." + strings.TrimPrefix(digest, "sha256:"), Digest: digest, Bytes: content},
	})
	if err != nil {
		t.Fatal(err)
	}
	return store, acceptedRoot
}

func acceptedRootCount(t *testing.T, store string) int {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(store, "accepted"))
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}
