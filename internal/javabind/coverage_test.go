package javabind

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// repoRoot resolves the repository root from this test file's own location, so
// the tests do not depend on the working directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate this test file")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(file), "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func loadAll(t *testing.T) (Spec, Receipt, Catalog, ArtifactIdentity, ArtifactIdentity, ArtifactIdentity) {
	t.Helper()
	root := repoRoot(t)
	specBytes, specIdentity, err := LoadArtifact(root, SpecPath)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := DecodeSpec(specBytes)
	if err != nil {
		t.Fatal(err)
	}
	catalogBytes, catalogIdentity, err := LoadArtifact(root, CatalogPath)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := DecodeCatalog(catalogBytes)
	if err != nil {
		t.Fatal(err)
	}
	receiptBytes, receiptIdentity, err := LoadArtifact(root, ReceiptPath)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := DecodeReceipt(receiptBytes)
	if err != nil {
		t.Fatal(err)
	}
	return spec, receipt, catalog, specIdentity, catalogIdentity, receiptIdentity
}

// TestCatalogIsTheImmutableCodexCatalog pins the denominator by content. The
// catalog is the Codex plane's artifact, vendored here byte-identically; if it
// ever drifts from those bytes this test fails rather than the coverage
// silently being computed over a different denominator.
func TestCatalogIsTheImmutableCodexCatalog(t *testing.T) {
	root := repoRoot(t)
	data, identity, err := LoadArtifact(root, CatalogPath)
	if err != nil {
		t.Fatal(err)
	}
	const wantSHA = "sha256:21112518f48443b4e20ecae537bed72b8c9e19167ad00bc6f325bff9374cdf59"
	if identity.SHA256 != wantSHA {
		t.Fatalf("catalog digest is %s, want the immutable %s", identity.SHA256, wantSHA)
	}
	if got := gitBlobID(data); got != "be929320dc8f6e52a357a6124bc17fa1db197d2b" {
		t.Fatalf("catalog git blob id is %s, want the Codex original be929320dc8f6e52a357a6124bc17fa1db197d2b", got)
	}
	catalog, err := DecodeCatalog(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Obligations) != CatalogDenominator || len(catalog.JavaBindings) != CatalogDenominator {
		t.Fatalf("catalog holds %d obligations and %d java bindings", len(catalog.Obligations), len(catalog.JavaBindings))
	}
}

// TestEveryObligationIsAccountedForExactlyOnce is the counting guard: the
// denominator stays 24 and no obligation may be quietly dropped from either
// side of the ledger.
func TestEveryObligationIsAccountedForExactlyOnce(t *testing.T) {
	spec, _, catalog, _, _, _ := loadAll(t)
	seen := map[string]int{}
	for _, binding := range spec.Bindings {
		seen[binding.ObligationID]++
	}
	for _, unbound := range spec.Unbound {
		seen[unbound.ObligationID]++
	}
	if len(seen) != CatalogDenominator {
		t.Fatalf("the spec accounts for %d obligations, want %d", len(seen), CatalogDenominator)
	}
	for _, obligation := range catalog.Obligations {
		if seen[obligation.ObligationID] != 1 {
			t.Fatalf("obligation %q is accounted for %d times", obligation.ObligationID, seen[obligation.ObligationID])
		}
	}
}

// TestRetainedProjectionIsExactlyWhatTheEvidenceDerives is the load-bearing
// check: the stored coverage numbers are recomputed here from the spec, the
// receipt and the catalog, and compared byte for byte against the retained file.
// A number edited into the artifact by hand cannot survive it.
func TestRetainedProjectionIsExactlyWhatTheEvidenceDerives(t *testing.T) {
	root := repoRoot(t)
	derived, err := Verify(root)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	encoded, err := MarshalArtifact(derived)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(ProjectionPath)))
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != string(encoded) {
		t.Fatal("the retained coverage projection is not what the retained evidence derives")
	}
}

// TestDerivedCountsAreExactAndSumToTheDenominator states the achieved coverage
// as a measurement. The expected values are written down here so that a change
// in the evidence that moves them has to be acknowledged in code review rather
// than sliding through.
func TestDerivedCountsAreExactAndSumToTheDenominator(t *testing.T) {
	projection, err := Verify(repoRoot(t))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	counts := projection.Counts
	if counts.Denominator != CatalogDenominator {
		t.Fatalf("denominator %d", counts.Denominator)
	}
	if counts.JavaBindingsConnected+counts.JavaBindingsPartial+counts.JavaBindingsDisconnected != CatalogDenominator {
		t.Fatalf("states do not partition the denominator: %+v", counts)
	}
	if len(projection.Obligations) != CatalogDenominator {
		t.Fatalf("projection has %d rows", len(projection.Obligations))
	}
	want := Counts{
		Denominator:                    24,
		JavaBindingsConnected:          4,
		JavaBindingsPartial:            2,
		JavaBindingsDisconnected:       18,
		JavaMutationSensitive:          6,
		JavaBindingsAtRequiredStrength: 0,
		Refinement:                     0,
		Aggregate:                      0,
		ClausesDeclared:                11,
		ClausesSatisfied:               9,
		CanariesDeclared:               10,
		CanariesKilled:                 10,
	}
	if counts != want {
		t.Fatalf("derived counts %+v, want %+v", counts, want)
	}
}

// TestNothingReachesTheStrengthTheCatalogRequires guards the claim ceiling. The
// Java side of this work is an executed observation, not a refinement, and no
// arithmetic anywhere may promote it.
func TestNothingReachesTheStrengthTheCatalogRequires(t *testing.T) {
	projection, err := Verify(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if projection.ObservedStrength != ObservedStrength || projection.RequiredStrength != RequiredStrength {
		t.Fatalf("strength labels are %q / %q", projection.ObservedStrength, projection.RequiredStrength)
	}
	if projection.Counts.JavaBindingsAtRequiredStrength != 0 || projection.Counts.Refinement != 0 || projection.Counts.Aggregate != 0 {
		t.Fatalf("a strength, refinement or aggregate numerator moved: %+v", projection.Counts)
	}
	for _, row := range projection.Obligations {
		if row.MeetsRequired {
			t.Fatalf("obligation %q claims it meets PRODUCTION_REFINEMENT", row.ObligationID)
		}
		if row.RequiredStrength != RequiredStrength {
			t.Fatalf("obligation %q declares required strength %q", row.ObligationID, row.RequiredStrength)
		}
	}
}

// TestConnectedBindingsSatisfyEveryClauseWithAKilledCanary spells out the
// counting rule the projection implements, independently of the projection.
func TestConnectedBindingsSatisfyEveryClauseWithAKilledCanary(t *testing.T) {
	projection, err := Verify(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	connected := 0
	for _, row := range projection.Obligations {
		if row.BindingState != StateConnected {
			continue
		}
		connected++
		if len(row.Clauses) == 0 {
			t.Fatalf("%q is CONNECTED with no clauses", row.ObligationID)
		}
		for _, clause := range row.Clauses {
			if !clause.Satisfied || !clause.WitnessesHold {
				t.Fatalf("%q is CONNECTED but clause %q is not satisfied", row.ObligationID, clause.ClauseID)
			}
			if clause.Mutation == nil || !clause.Mutation.Applied || !clause.Mutation.Killed || !clause.Mutation.ControlAgrees {
				t.Fatalf("%q clause %q is CONNECTED without an applied, controlled, killed canary", row.ObligationID, clause.ClauseID)
			}
		}
	}
	if connected != projection.Counts.JavaBindingsConnected {
		t.Fatalf("counted %d connected rows, projection says %d", connected, projection.Counts.JavaBindingsConnected)
	}
}

// TestEveryCanaryIsInsideItsBoundSpan is the attribution guard. A canary outside
// the declaration the binding names would prove nothing about that declaration.
func TestEveryCanaryIsInsideItsBoundSpan(t *testing.T) {
	spec, receipt, _, _, _, _ := loadAll(t)
	for _, binding := range spec.Bindings {
		for _, mutation := range binding.Mutations() {
			application, ok := receipt.MutationApplication(mutation.MutationID)
			if !ok {
				t.Fatalf("mutation %q has no recorded application", mutation.MutationID)
			}
			construct, ok := receipt.Construct(binding.ObligationID, mutation.ChainMember)
			if !ok {
				t.Fatalf("mutation %q names an unresolved chain member", mutation.MutationID)
			}
			if application.AbsoluteOffset < construct.Start ||
				application.AbsoluteOffset+application.Length > construct.End {
				t.Fatalf("mutation %q at [%d,%d) is outside the bound span [%d,%d)",
					mutation.MutationID, application.AbsoluteOffset, application.AbsoluteOffset+application.Length,
					construct.Start, construct.End)
			}
			if application.ControlRuntime == application.MutantRuntime {
				t.Fatalf("mutation %q control and mutant archives are identical", mutation.MutationID)
			}
		}
	}
}

// TestEveryControlReproducesItsBaseline is what makes a mutant difference
// attributable to the edit rather than to recompiling and repackaging.
func TestEveryControlReproducesItsBaseline(t *testing.T) {
	_, receipt, _, _, _, _ := loadAll(t)
	controls := 0
	for _, run := range receipt.Runs {
		if !strings.HasPrefix(run.Variant, "CONTROL:") {
			continue
		}
		controls++
		baseline, ok := receipt.Run(run.ScenarioID, VariantBaseline)
		if !ok {
			t.Fatalf("control %q has no baseline", run.RunID)
		}
		controlProjection, err := SemanticProjection([]byte(run.ResponseLine))
		if err != nil {
			t.Fatal(err)
		}
		baselineProjection, err := SemanticProjection([]byte(baseline.ResponseLine))
		if err != nil {
			t.Fatal(err)
		}
		if string(controlProjection) != string(baselineProjection) {
			t.Fatalf("control %q does not reproduce its baseline observation", run.RunID)
		}
		if run.ResponseLine == baseline.ResponseLine {
			t.Fatalf("control %q is byte-identical to the baseline, so it did not load a repackaged archive", run.RunID)
		}
	}
	if controls == 0 {
		t.Fatal("no control runs are retained; mutant differences would not be attributable")
	}
}

// TestTamperedResponseFailsVerification is the deletion attack in test form: a
// retained response is altered in memory and the check must reject it.
func TestTamperedResponseFailsVerification(t *testing.T) {
	spec, receipt, _, _, _, _ := loadAll(t)
	if err := receipt.VerifyDigests(spec); err != nil {
		t.Fatalf("the untouched receipt must verify: %v", err)
	}
	tampered := receipt
	tampered.Runs = append([]Run(nil), receipt.Runs...)
	// Flip one byte of one retained response, leaving its recorded digest alone.
	original := tampered.Runs[0].ResponseLine
	tampered.Runs[0].ResponseLine = original[:len(original)-1] + " "
	if tampered.Runs[0].ResponseLine == original {
		t.Fatal("the tamper did not change the response line")
	}
	if err := tampered.VerifyDigests(spec); err == nil {
		t.Fatal("an edited response line must fail digest verification")
	}
}

// TestTamperedRuntimeBindingFailsVerification: a response that does not bind the
// archive the receipt says it ran against must be rejected.
func TestTamperedRuntimeBindingFailsVerification(t *testing.T) {
	spec, receipt, _, _, _, _ := loadAll(t)
	tampered := receipt
	tampered.PinnedRuntime.SHA256 = "sha256:" + strings.Repeat("0", 64)
	if err := tampered.VerifyDigests(spec); err == nil {
		t.Fatal("a receipt whose pinned runtime does not match its baseline responses must be rejected")
	}
}

// TestTamperedCountFailsTheProjectionComparison: editing a number into the
// artifact without the evidence changing must not survive.
func TestTamperedCountFailsTheProjectionComparison(t *testing.T) {
	root := repoRoot(t)
	derived, err := Verify(root)
	if err != nil {
		t.Fatal(err)
	}
	inflated := derived
	inflated.Counts.JavaBindingsConnected += 1
	encoded, err := MarshalArtifact(inflated)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(ProjectionPath)))
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) == string(encoded) {
		t.Fatal("an inflated numerator compared equal to the retained artifact")
	}
}

// TestSemanticProjectionRemovesOnlyTheRuntimeBlock keeps the control comparison
// honest: it must not be able to hide an observable difference.
func TestSemanticProjectionRemovesOnlyTheRuntimeBlock(t *testing.T) {
	line := `{"counts":{"frames":1},"outcome":"ok","runtime":{"sha256":"sha256:abc"}}`
	projected, err := SemanticProjection([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(projected, &got); err != nil {
		t.Fatal(err)
	}
	if _, present := got["runtime"]; present {
		t.Fatal("the runtime block must be removed")
	}
	if len(got) != 2 || got["outcome"] != "ok" {
		t.Fatalf("the projection dropped an observable: %v", got)
	}
	differing := `{"counts":{"frames":2},"outcome":"ok","runtime":{"sha256":"sha256:abc"}}`
	other, err := SemanticProjection([]byte(differing))
	if err != nil {
		t.Fatal(err)
	}
	if string(other) == string(projected) {
		t.Fatal("the projection hid a difference in an observable")
	}
}

// TestApplyMutationRefusesUnanchoredEdits: a canary that does not match the
// pinned bytes, or that reaches outside the bound span, must be refused.
func TestApplyMutationRefusesUnanchoredEdits(t *testing.T) {
	file := []byte("aaaaBBBBcccc")
	construct := SourceConstruct{Start: 4, End: 8, ObligationID: "o", SourceFile: "f", FileSHA256: Digest(file)}
	good := Mutation{MutationID: "m", ChainMember: "x", RelativeOffset: 0, Length: 4, RemovedSHA256: Digest([]byte("BBBB")), Replacement: "zz"}
	mutated, application, err := ApplyMutation(file, construct, good)
	if err != nil {
		t.Fatalf("a correctly anchored mutation must apply: %v", err)
	}
	if string(mutated) != "aaaazzcccc" || application.AbsoluteOffset != 4 {
		t.Fatalf("unexpected splice %q %+v", mutated, application)
	}

	wrongDigest := good
	wrongDigest.RemovedSHA256 = Digest([]byte("CCCC"))
	if _, _, err := ApplyMutation(file, construct, wrongDigest); err == nil {
		t.Fatal("a mutation whose removed bytes do not hash to the recorded value must be refused")
	}
	outside := good
	outside.RelativeOffset = 3
	outside.Length = 4
	if _, _, err := ApplyMutation(file, construct, outside); err == nil {
		t.Fatal("a mutation reaching outside the bound span must be refused")
	}
}

// TestPredicateVocabularyIsClosed: a predicate the evaluator does not know must
// be a spec error, never a silently-true assertion.
func TestPredicateVocabularyIsClosed(t *testing.T) {
	if err := (Predicate{Kind: "vibes", String: "good"}).Validate(); err == nil {
		t.Fatal("an unknown predicate kind must be rejected")
	}
	if err := (Predicate{Kind: "outcome"}).Validate(); err == nil {
		t.Fatal("a predicate missing its operand must be rejected")
	}
	spec, _, _, _, _, _ := loadAll(t)
	for _, binding := range spec.Bindings {
		for _, clause := range binding.Clauses {
			for _, witness := range clause.Witnesses {
				if !PredicateKinds[witness.Predicate.Kind] {
					t.Fatalf("clause %q uses predicate kind %q", clause.ClauseID, witness.Predicate.Kind)
				}
			}
		}
	}
}

// TestUnboundObligationsCarryTypedReasons: an unbound obligation is a recorded
// fact with a code from a closed vocabulary, not an omission.
func TestUnboundObligationsCarryTypedReasons(t *testing.T) {
	projection, err := Verify(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range projection.Obligations {
		if len(row.Clauses) > 0 {
			continue
		}
		if !UnboundReasonCodes[row.ReasonCode] {
			t.Fatalf("obligation %q is unbound with reason code %q", row.ObligationID, row.ReasonCode)
		}
		if len(row.ReasonDetail) < 40 {
			t.Fatalf("obligation %q gives no substantive reason", row.ObligationID)
		}
	}
}

// TestEveryBindingEchoesTheCatalogSymbolUnmodified: the binding may not quietly
// rebind an obligation to a symbol the immutable catalog does not name.
func TestEveryBindingEchoesTheCatalogSymbolUnmodified(t *testing.T) {
	spec, _, catalog, _, _, _ := loadAll(t)
	for _, binding := range spec.Bindings {
		declared, ok := catalog.JavaBinding(binding.ObligationID)
		if !ok {
			t.Fatalf("catalog has no java binding for %q", binding.ObligationID)
		}
		if binding.CatalogSymbol != declared.ProductionSymbol {
			t.Fatalf("binding %q echoes %q but the catalog declares %q", binding.ObligationID, binding.CatalogSymbol, declared.ProductionSymbol)
		}
		_, member, _ := SymbolDescriptor(declared.ProductionSymbol)
		if member != "" && binding.Chain[0] != member {
			t.Fatalf("binding %q roots its chain at %q, not the catalog's %q", binding.ObligationID, binding.Chain[0], member)
		}
	}
}

// TestProjectionStatesItsOwnCeiling: a reader who quotes only the JSON still
// gets the qualification.
func TestProjectionStatesItsOwnCeiling(t *testing.T) {
	projection, err := Verify(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if projection.Assurance.Assurance != "OWNER_ATTESTED_NOT_INDEPENDENT" || projection.Assurance.IndependentReviewClaim {
		t.Fatalf("assurance labelling is %+v", projection.Assurance)
	}
	joined := strings.ToLower(strings.Join(projection.Claim.NotClaims, " | "))
	for _, required := range []string{"not a proof of the java library", "formally verified", "refinement", "aggregate", "not independent"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("the claim block does not disclaim %q", required)
		}
	}
	if projection.Claim.Statement == "" {
		t.Fatal("the projection carries no claim statement")
	}
}
