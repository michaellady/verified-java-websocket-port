package main

import (
	"strings"
	"testing"
)

func TestApplyEditsRequiresTheExactDeclaredCount(t *testing.T) {
	updated, err := applyEdits("alpha beta alpha", []edit{{Find: "alpha", Replace: "gamma", Count: 2}})
	if err != nil || updated != "gamma beta gamma" {
		t.Fatalf("updated=%q err=%v", updated, err)
	}
	for _, candidate := range []edit{
		{Find: "absent", Replace: "x", Count: 1},
		{Find: "alpha", Replace: "alpha", Count: 2},
		{Find: "alpha", Replace: "x", Count: 0},
	} {
		if _, err := applyEdits("alpha beta alpha", []edit{candidate}); err == nil {
			t.Fatalf("unsafe edit passed: %#v", candidate)
		}
	}
}

func TestClassifyReadsAllTLCViolationFormsAndTheCleanVerdict(t *testing.T) {
	cases := []struct {
		body    string
		verdict string
		check   string
	}{
		{"Error: Invariant TypeOK is violated.", "violated", "TypeOK"},
		{"Error: Temporal property ClosingResolves was violated.", "violated", "ClosingResolves"},
		{"Error: Action property TerminalAbsorbing is violated.", "violated", "TerminalAbsorbing"},
		{"Model checking completed. No error has been found.", "clean", "NONE"},
		{"unrelated", "indeterminate", "NONE"},
	}
	for _, candidate := range cases {
		verdict, check := classify(candidate.body)
		if verdict != candidate.verdict || check != candidate.check {
			t.Fatalf("classify(%q)=(%q,%q)", candidate.body, verdict, check)
		}
	}
}

func TestValidateManifestRejectsUnsafeOrVacuousMutations(t *testing.T) {
	valid := manifest{
		SchemaVersion: "1.0.0",
		Kind:          "formal-model-mutations",
		ToolSHA256:    "sha256:" + strings.Repeat("a", 64),
		Models:        []model{{Module: "ConnectionModel", TLAPath: "assurance/model.tla", CFGPath: "assurance/model.cfg"}},
		Mutations: []mutation{{
			ID: "terminal-duplicate", Module: "ConnectionModel", Target: "tla",
			ExpectedExit: 12, ExpectedKind: "violated", ExpectedCheck: "TerminalAtMostOnce",
			Rationale: "a deliberate duplicate terminal transition must be rejected",
			Edits:     []edit{{Find: "guard", Replace: "TRUE", Count: 1}},
		}},
	}
	if err := validateManifest(valid); err != nil {
		t.Fatal(err)
	}
	invalid := valid
	invalid.Models = []model{{Module: "ConnectionModel", TLAPath: "../escape.tla", CFGPath: "model.cfg"}}
	if err := validateManifest(invalid); err == nil {
		t.Fatal("parent traversal passed")
	}
	invalid = valid
	invalid.Mutations[0].ExpectedExit = 0
	if err := validateManifest(invalid); err == nil {
		t.Fatal("zero-exit mutant passed")
	}
}

func TestValidateCheckCoverageRequiresOneMutationPerConfiguredCheck(t *testing.T) {
	plan := manifest{
		Models: []model{{Module: "ConnectionModel"}},
		Mutations: []mutation{
			{Module: "ConnectionModel", ExpectedCheck: "TypeOK"},
			{Module: "ConnectionModel", ExpectedCheck: "EventuallyClosed"},
		},
	}
	staged := map[string]map[string][]byte{
		"ConnectionModel": {"cfg": []byte("SPECIFICATION Spec\nINVARIANT TypeOK\nPROPERTY EventuallyClosed\n")},
	}
	if err := validateCheckCoverage(plan, staged); err != nil {
		t.Fatal(err)
	}
	plan.Mutations = plan.Mutations[:1]
	if err := validateCheckCoverage(plan, staged); err == nil {
		t.Fatal("missing property mutation passed")
	}
}
