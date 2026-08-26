package corpora

import (
	"bytes"
	"strings"
	"testing"
)

func testInput() GenerationInput {
	return GenerationInput{
		PublicSeed: "us005-public-calibration-seed-v1",
		Secret:     "8e5d271c9d3aa2f4c05b7a1e6f08d94433bb92a1c6d0e8f7355a4b2c1d9e0f68",
		Epoch:      1,
	}
}

// Generation must be fully deterministic: two runs from the same seeds must
// reconcile byte-for-byte, with zero flakes.
func TestGenerateAllIsDeterministic(t *testing.T) {
	first, err := GenerateAll(testInput())
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}
	second, err := GenerateAll(testInput())
	if err != nil {
		t.Fatalf("GenerateAll rerun: %v", err)
	}
	a, err := first.CanonicalDigest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	b, err := second.CanonicalDigest()
	if err != nil {
		t.Fatalf("digest rerun: %v", err)
	}
	if a != b {
		t.Fatalf("generation is not deterministic: %s vs %s", a, b)
	}
}

// The behavior tiers must be distinct, every scenario derivable, and every
// scenario id unique and oracle-request-id safe.
func TestGenerateAllTiersAreDistinctAndWellFormed(t *testing.T) {
	generated, err := GenerateAll(testInput())
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}
	tiers := map[string][]Scenario{
		"public": generated.Public, "hidden": generated.Hidden, "sealed": generated.Sealed}
	seen := map[string]bool{}
	contentDigests := map[string]string{}
	for tier, scenarios := range tiers {
		if len(scenarios) == 0 {
			t.Fatalf("tier %s is empty", tier)
		}
		for _, sc := range scenarios {
			if sc.Tier != tier {
				t.Fatalf("scenario %s carries tier %s in tier %s", sc.ScenarioID, sc.Tier, tier)
			}
			if seen[sc.ScenarioID] {
				t.Fatalf("duplicate scenario id %s", sc.ScenarioID)
			}
			seen[sc.ScenarioID] = true
			for _, r := range sc.ScenarioID {
				if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-", r) {
					t.Fatalf("scenario id %q is not oracle request-id safe", sc.ScenarioID)
				}
			}
			if sc.ExpectationStatus != ExpectationStatusReferenceModel {
				t.Fatalf("scenario %s status %q", sc.ScenarioID, sc.ExpectationStatus)
			}
			if len(sc.ExpectationBasis) == 0 {
				t.Fatalf("scenario %s has no expectation basis", sc.ScenarioID)
			}
			// Every committed expectation must re-derive identically.
			rederived, err := DeriveExpected(sc.Core)
			if err != nil {
				t.Fatalf("scenario %s is not derivable: %v", sc.ScenarioID, err)
			}
			left, _ := CanonicalJSON(rederived.toMap())
			right, _ := CanonicalJSON(sc.Expected.toMap())
			if !bytes.Equal(left, right) {
				t.Fatalf("scenario %s expectation does not re-derive", sc.ScenarioID)
			}
			line, err := sc.CanonicalLine()
			if err != nil {
				t.Fatalf("scenario %s canonical line: %v", sc.ScenarioID, err)
			}
			contentDigests[tier+":"+sc.ScenarioID] = DigestSHA256(line)
		}
	}
	// Hidden and sealed content must differ from public content.
	publicLines := map[string]bool{}
	for _, sc := range generated.Public {
		line, _ := sc.CanonicalLine()
		publicLines[DigestSHA256(line)] = true
	}
	for _, sc := range append(append([]Scenario{}, generated.Hidden...), generated.Sealed...) {
		line, _ := sc.CanonicalLine()
		if publicLines[DigestSHA256(line)] {
			t.Fatalf("held-out scenario %s duplicates public content", sc.ScenarioID)
		}
	}
}

// Outcome coverage: each tier must include both success and error outcomes,
// both roles, byte input, local commands, limits, close details, and counts.
func TestGenerateBehaviorCoverage(t *testing.T) {
	generated, err := GenerateAll(testInput())
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}
	for tier, scenarios := range map[string][]Scenario{
		"public": generated.Public, "hidden": generated.Hidden, "sealed": generated.Sealed} {
		var ok, errOutcome, server, client, bytesSteps, actions, closes, limits int
		for _, sc := range scenarios {
			if sc.Expected.Outcome == "ok" {
				ok++
				if sc.Expected.Counts == nil {
					t.Fatalf("%s: ok scenario %s without counts", tier, sc.ScenarioID)
				}
			} else {
				errOutcome++
			}
			if sc.Core.Role == "server" {
				server++
			} else {
				client++
			}
			for _, step := range sc.Core.Steps {
				if step.Kind == "bytes" {
					bytesSteps++
				} else {
					actions++
				}
			}
			if sc.Expected.Close != nil {
				closes++
			}
			if sc.Expected.Error != nil &&
				strings.Contains(sc.Expected.Error.Code, "LIMIT") {
				limits++
			}
		}
		for name, count := range map[string]int{"ok": ok, "error": errOutcome,
			"server": server, "client": client, "bytes": bytesSteps,
			"actions": actions, "closes": closes, "limit errors": limits} {
			if count == 0 {
				t.Fatalf("tier %s lacks %s coverage", tier, name)
			}
		}
	}
}

// The handshake corpus must cover valid and invalid requests and responses,
// partial input, and configured limits, with derived accept values.
func TestGenerateHandshakeCoverage(t *testing.T) {
	generated, err := GenerateAll(testInput())
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}
	if len(generated.Handshake) == 0 {
		t.Fatal("handshake corpus is empty")
	}
	var accept, rejectVerdict, incomplete, requests, responses, limits int
	seen := map[string]bool{}
	for _, c := range generated.Handshake {
		if seen[c.CaseID] {
			t.Fatalf("duplicate case id %s", c.CaseID)
		}
		seen[c.CaseID] = true
		switch c.Expected.Verdict {
		case "accept":
			accept++
			if c.Direction == "client_request" && c.Expected.SecWebSocketAccept == "" {
				t.Fatalf("case %s: accepted request without derived accept value", c.CaseID)
			}
		case "reject":
			rejectVerdict++
		case "incomplete":
			incomplete++
		default:
			t.Fatalf("case %s verdict %q", c.CaseID, c.Expected.Verdict)
		}
		if c.Direction == "client_request" {
			requests++
		} else {
			responses++
		}
		if strings.HasPrefix(c.Expected.RejectCode, "HS_LIMIT_") {
			limits++
		}
	}
	for name, count := range map[string]int{"accept": accept, "reject": rejectVerdict,
		"incomplete": incomplete, "requests": requests, "responses": responses,
		"limit rejections": limits} {
		if count == 0 {
			t.Fatalf("handshake corpus lacks %s coverage", name)
		}
	}
}

// Canaries: hidden and sealed carry seeded anti-evasion canaries whose ids are
// recorded in the inventory and whose payloads embed secret-derived tokens.
func TestGenerateCanaries(t *testing.T) {
	generated, err := GenerateAll(testInput())
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}
	for _, tier := range []string{"hidden", "sealed"} {
		ids := generated.CanaryIDs[tier]
		if len(ids) == 0 {
			t.Fatalf("tier %s has no canaries", tier)
		}
		scenarios := generated.Hidden
		if tier == "sealed" {
			scenarios = generated.Sealed
		}
		byID := map[string]Scenario{}
		for _, sc := range scenarios {
			byID[sc.ScenarioID] = sc
		}
		for _, id := range ids {
			sc, found := byID[id]
			if !found {
				t.Fatalf("canary %s not present in tier %s", id, tier)
			}
			token := generated.CanaryTokens[id]
			if token == "" {
				t.Fatalf("canary %s has no token", id)
			}
			line, _ := sc.CanonicalLine()
			if !bytes.Contains(line, []byte(token)) {
				t.Fatalf("canary %s does not embed its token", id)
			}
		}
	}
	if len(generated.CanaryIDs["public"]) != 0 {
		t.Fatal("public tier must not contain canaries")
	}
}

// Rotation: a new epoch re-derives hidden and sealed content while public
// and handshake corpora remain stable.
func TestGenerateRotationEpoch(t *testing.T) {
	base, err := GenerateAll(testInput())
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}
	rotated := testInput()
	rotated.Epoch = 2
	next, err := GenerateAll(rotated)
	if err != nil {
		t.Fatalf("GenerateAll epoch 2: %v", err)
	}
	basePublic, _ := tierDigest(base.Public)
	nextPublic, _ := tierDigest(next.Public)
	if basePublic != nextPublic {
		t.Fatal("rotation must not disturb the public tier")
	}
	baseHidden, _ := tierDigest(base.Hidden)
	nextHidden, _ := tierDigest(next.Hidden)
	if baseHidden == nextHidden {
		t.Fatal("rotation must re-derive the hidden tier")
	}
	baseSealed, _ := tierDigest(base.Sealed)
	nextSealed, _ := tierDigest(next.Sealed)
	if baseSealed == nextSealed {
		t.Fatal("rotation must re-derive the sealed tier")
	}
}

// Plan counts are derived from generation, never hand-typed: expected equals
// the plan expansion, selected equals emitted scenarios, and the difference
// is the filtered count.
func TestGeneratePlanCountsReconcile(t *testing.T) {
	generated, err := GenerateAll(testInput())
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}
	for tier, scenarios := range map[string][]Scenario{
		"public": generated.Public, "hidden": generated.Hidden, "sealed": generated.Sealed} {
		plan := generated.PlanCounts[tier]
		if plan.Selected != len(scenarios) {
			t.Fatalf("tier %s selected=%d emitted=%d", tier, plan.Selected, len(scenarios))
		}
		if plan.Expected != plan.Selected+plan.Filtered {
			t.Fatalf("tier %s expected=%d selected=%d filtered=%d",
				tier, plan.Expected, plan.Selected, plan.Filtered)
		}
	}
	plan := generated.PlanCounts["handshake"]
	if plan.Selected != len(generated.Handshake) ||
		plan.Expected != plan.Selected+plan.Filtered {
		t.Fatalf("handshake plan counts do not reconcile: %+v", plan)
	}
}

// Held-out tiers carry structural boundary families pinned from the
// quarantined runtime sources; the public tier does not.
func TestHeldOutStructuralFamilies(t *testing.T) {
	generated, err := GenerateAll(testInput())
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}
	families := func(scenarios []Scenario) map[string]int {
		out := map[string]int{}
		for _, sc := range scenarios {
			out[sc.Family]++
		}
		return out
	}
	publicFamilies := families(generated.Public)
	heldOutOnly := []string{"close-code-1012-1014", "close-code-reserved-range",
		"close-invalid-utf8-reason", "close-1007-empty-reason", "send-oversize-ping",
		"send-fragment-single", "fragment-overflow-nonfin", "fragment-overflow-fin",
		"send-close-1015"}
	for _, tierScenarios := range [][]Scenario{generated.Hidden, generated.Sealed} {
		tierFamilies := families(tierScenarios)
		for _, family := range heldOutOnly {
			if tierFamilies[family] == 0 {
				t.Fatalf("held-out tier lacks family %s", family)
			}
			if publicFamilies[family] != 0 {
				t.Fatalf("family %s leaked into the public tier", family)
			}
		}
	}
	// Spot-check pinned semantics of the new families.
	byFamily := func(scenarios []Scenario, family string) []Scenario {
		var out []Scenario
		for _, sc := range scenarios {
			if sc.Family == family {
				out = append(out, sc)
			}
		}
		return out
	}
	for _, sc := range byFamily(generated.Hidden, "close-code-1012-1014") {
		if sc.Expected.Outcome != "ok" {
			t.Fatalf("%s: 1012-1014 must be valid, got %+v", sc.ScenarioID, sc.Expected.Error)
		}
	}
	for _, sc := range byFamily(generated.Hidden, "close-code-reserved-range") {
		if sc.Expected.Outcome != "error" || *sc.Expected.Error.CloseCode != 1002 {
			t.Fatalf("%s: 1016-2999 must fail 1002", sc.ScenarioID)
		}
	}
	for _, sc := range byFamily(generated.Hidden, "close-invalid-utf8-reason") {
		if sc.Expected.Error == nil || sc.Expected.Error.Code != "JAVA_RUNTIME_REJECTION" {
			t.Fatalf("%s: invalid-utf8 close reason must be JAVA_RUNTIME_REJECTION", sc.ScenarioID)
		}
	}
	for _, sc := range byFamily(generated.Hidden, "fragment-overflow-nonfin") {
		if sc.Expected.Error == nil || sc.Expected.Error.Code != "BUFFER_LIMIT_EXCEEDED" {
			t.Fatalf("%s: nonfin overflow must be BUFFER_LIMIT_EXCEEDED", sc.ScenarioID)
		}
	}
	for _, sc := range byFamily(generated.Hidden, "fragment-overflow-fin") {
		if sc.Expected.Error == nil || *sc.Expected.Error.CloseCode != 1009 {
			t.Fatalf("%s: fin overflow must be 1009", sc.ScenarioID)
		}
	}
	for _, sc := range byFamily(generated.Hidden, "send-oversize-ping") {
		if sc.Expected.Outcome != "ok" {
			t.Fatalf("%s: oversize send_ping must succeed", sc.ScenarioID)
		}
	}
}
