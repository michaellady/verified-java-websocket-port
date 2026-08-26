package formalplan

// Lane B (US-006) tests for the connection-model TLA validator. All helper
// identifiers are lane-scoped (mpTest* prefix) so Lane A files can land in
// this package in either order without collisions.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	mpTestTLAPath  = "../../assurance/formal/connection-model.tla"
	mpTestCfgPath  = "../../assurance/formal/connection-model.cfg"
	mpTestJavaRoot = "../../.quarantine/Java-WebSocket-da3cf2a777aed862f2f5b5cf060cae7969958667/src/main/java/org/java_websocket"
)

func mpTestJavaRootIfPresent(t *testing.T) string {
	t.Helper()
	info, err := os.Stat(mpTestJavaRoot)
	if err != nil || !info.IsDir() {
		return ""
	}
	return mpTestJavaRoot
}

func mpTestReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func mpTestWriteFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func mpTestHasFinding(findings []ModelFinding, code string) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}

func mpTestBlocking(findings []ModelFinding) []ModelFinding {
	var blocking []ModelFinding
	for _, finding := range findings {
		if finding.Severity == SeverityBlocking {
			blocking = append(blocking, finding)
		}
	}
	return blocking
}

func TestConnectionModelArtifactsValidate(t *testing.T) {
	root := mpTestJavaRootIfPresent(t)
	findings := ValidateConnectionModel(mpTestTLAPath, mpTestCfgPath, root)
	if blocking := mpTestBlocking(findings); len(blocking) != 0 {
		t.Fatalf("shipped connection model has blocking findings: %+v", blocking)
	}
	if root != "" && len(findings) != 0 {
		t.Fatalf("shipped connection model has findings with quarantine present: %+v", findings)
	}
	if root == "" && !mpTestHasFinding(findings, "MODEL_CITATION_UNVERIFIED") {
		t.Fatalf("expected advisory MODEL_CITATION_UNVERIFIED without quarantine, got %+v", findings)
	}
}

func TestConnectionModelValidatorRejectsStructuralDefects(t *testing.T) {
	tla := mpTestReadFile(t, mpTestTLAPath)
	cfg := mpTestReadFile(t, mpTestCfgPath)
	root := mpTestJavaRootIfPresent(t)

	mustContain := func(t *testing.T, haystack, needle string) {
		t.Helper()
		if !strings.Contains(haystack, needle) {
			t.Fatalf("shipped artifact no longer contains %q; update the test mutation", needle)
		}
	}

	cases := []struct {
		name    string
		tla     func(string) string
		cfg     func(string) string
		expect  string
		mention string
	}{
		{
			name:   "module header renamed",
			tla:    func(s string) string { return strings.Replace(s, "MODULE ConnectionModel", "MODULE RenamedModel", 1) },
			expect: "MODEL_HEADER_MISSING",
		},
		{
			name:   "staging note removed",
			tla:    func(s string) string { return strings.ReplaceAll(s, "STAGE AS: ConnectionModel.tla", "note removed") },
			expect: "MODEL_STAGING_NOTE_MISSING",
		},
		{
			name:   "model-check status removed",
			tla:    func(s string) string { return strings.ReplaceAll(s, "\\* MODEL_CHECK:", "\\* model check:") },
			expect: "MODEL_CHECK_STATUS_MISSING",
		},
		{
			name:    "constant unconfigured",
			cfg:     func(s string) string { return strings.Replace(s, "MaxInbound = 3", "", 1) },
			expect:  "TLA_CONSTANT_UNCONFIGURED",
			mention: "MaxInbound",
		},
		{
			name:   "extra cfg constant",
			cfg:    func(s string) string { return strings.Replace(s, "MaxInbound = 3", "MaxInbound = 3\n    Bogus = 4", 1) },
			expect: "TLA_CFG_EXTRA_CONSTANT",
		},
		{
			name:   "non-positive constant",
			cfg:    func(s string) string { return strings.Replace(s, "QueueCapacity = 2", "QueueCapacity = 0", 1) },
			expect: "TLA_CFG_CONSTANT_NOT_POSITIVE",
		},
		{
			name:   "non-integer constant",
			cfg:    func(s string) string { return strings.Replace(s, "QueueCapacity = 2", "QueueCapacity = {1, 2}", 1) },
			expect: "TLA_CFG_CONSTANT_NOT_POSITIVE",
		},
		{
			name:   "specification undefined",
			cfg:    func(s string) string { return strings.Replace(s, "SPECIFICATION FairSpec", "SPECIFICATION MissingSpec", 1) },
			expect: "TLA_SPECIFICATION_UNDEFINED",
		},
		{
			name:   "invariant undefined",
			cfg:    func(s string) string { return s + "\nINVARIANT NoSuchInvariant\n" },
			expect: "TLA_INVARIANT_UNDEFINED",
		},
		{
			name:   "property undefined",
			cfg:    func(s string) string { return s + "\nPROPERTY NoSuchProperty\n" },
			expect: "TLA_PROPERTY_UNDEFINED",
		},
		{
			name: "primed invariant",
			tla: func(s string) string {
				return strings.Replace(s,
					"QueueNeverExceedsCapacity == Len(outQ) <= QueueCapacity",
					"QueueNeverExceedsCapacity == Len(outQ') <= QueueCapacity", 1)
			},
			expect: "TLA_PRIMED_INVARIANT",
		},
		{
			name: "temporal operator inside invariant",
			tla: func(s string) string {
				return strings.Replace(s,
					"QueueNeverExceedsCapacity == Len(outQ) <= QueueCapacity",
					"QueueNeverExceedsCapacity == [](Len(outQ) <= QueueCapacity)", 1)
			},
			expect: "TLA_TEMPORAL_INVARIANT",
		},
		{
			name:   "falsification note removed",
			tla:    func(s string) string { return strings.ReplaceAll(s, "\\* FALSIFIED BY:", "\\* note:") },
			expect: "TLA_MISSING_FALSIFICATION_NOTE",
		},
		{
			name:   "java citations removed",
			tla:    func(s string) string { return strings.ReplaceAll(s, "\\* JAVA:", "\\* ref:") },
			expect: "TLA_MISSING_JAVA_CITATION",
		},
		{
			name:   "rust duplicate implementation smuggled in",
			tla:    func(s string) string { return s + "\npub fn duplicate_state_machine() {}\n" },
			expect: "TLA_RUST_DUPLICATE_SUSPECT",
		},
		{
			name:   "block comment defeats static analysis",
			tla:    func(s string) string { return s + "\n(* hidden *)\n" },
			expect: "TLA_BLOCK_COMMENT_UNSUPPORTED",
		},
		{
			name:   "no invariants configured",
			cfg:    func(s string) string { return strings.ReplaceAll(s, "INVARIANT ", "\\* INVARIANT ") },
			expect: "TLA_NO_INVARIANT",
		},
		{
			name:   "carriage returns rejected",
			tla:    func(s string) string { return strings.Replace(s, "\n", "\r\n", 1) },
			expect: "MODEL_ENCODING_INVALID",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			mutatedTLA, mutatedCfg := tla, cfg
			if testCase.tla != nil {
				mutatedTLA = testCase.tla(tla)
				if mutatedTLA == tla {
					t.Fatalf("tla mutation was a no-op")
				}
			}
			if testCase.cfg != nil {
				mutatedCfg = testCase.cfg(cfg)
				if mutatedCfg == cfg {
					t.Fatalf("cfg mutation was a no-op")
				}
			}
			if testCase.mention != "" {
				mustContain(t, tla+cfg, testCase.mention)
			}
			dir := t.TempDir()
			tlaPath := mpTestWriteFile(t, dir, "connection-model.tla", mutatedTLA)
			cfgPath := mpTestWriteFile(t, dir, "connection-model.cfg", mutatedCfg)
			findings := ValidateConnectionModel(tlaPath, cfgPath, root)
			if !mpTestHasFinding(findings, testCase.expect) {
				t.Fatalf("expected finding %s, got %+v", testCase.expect, findings)
			}
		})
	}
}

func TestConnectionModelValidatorRejectsMissingFiles(t *testing.T) {
	findings := ValidateConnectionModel("does-not-exist.tla", "does-not-exist.cfg", "")
	if !mpTestHasFinding(findings, "MODEL_FILE_UNREADABLE") {
		t.Fatalf("expected MODEL_FILE_UNREADABLE, got %+v", findings)
	}
}

func TestConnectionModelCitationResolution(t *testing.T) {
	tla := mpTestReadFile(t, mpTestTLAPath)
	cfg := mpTestReadFile(t, mpTestCfgPath)
	root := mpTestJavaRootIfPresent(t)
	mutated := strings.Replace(tla,
		"\\* JAVA: WebSocketImpl.java:757-766",
		"\\* JAVA: WebSocketImpl.java:757000-766000", 1)
	if mutated == tla {
		t.Fatalf("citation mutation was a no-op; update the test anchor")
	}
	dir := t.TempDir()
	tlaPath := mpTestWriteFile(t, dir, "connection-model.tla", mutated)
	cfgPath := mpTestWriteFile(t, dir, "connection-model.cfg", cfg)
	findings := ValidateConnectionModel(tlaPath, cfgPath, root)
	if root != "" {
		if !mpTestHasFinding(findings, "MODEL_CITATION_UNRESOLVED") {
			t.Fatalf("expected MODEL_CITATION_UNRESOLVED with quarantine present, got %+v", findings)
		}
	} else if !mpTestHasFinding(findings, "MODEL_CITATION_UNVERIFIED") {
		t.Fatalf("expected advisory MODEL_CITATION_UNVERIFIED without quarantine, got %+v", findings)
	}
}

func TestModelValidationLimitsAreDocumented(t *testing.T) {
	for _, required := range []string{"SANY", "TLC", "vacuity"} {
		if !strings.Contains(ModelValidationLimits, required) {
			t.Fatalf("ModelValidationLimits must honestly document the %q gap", required)
		}
	}
}
