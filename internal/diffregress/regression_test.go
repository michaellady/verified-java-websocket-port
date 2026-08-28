package diffregress

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/corpora"
)

// TestCommittedArmsAgree is the standing differential assertion over the
// committed regression set: our recorded Rust arm must agree behaviorally with
// the recorded real-Java arm on every corpus-invisible probe. This runs in the
// default `go test ./...` because both arms are committed; the live re-run of
// our arm lives in rerun_test.go behind the `diffregress` build tag.
func TestCommittedArmsAgree(t *testing.T) {
	summary, err := CompareTranscripts(
		evidencePath(t, JavaArmFile),
		evidencePath(t, RustArmFile),
	)
	if err != nil {
		t.Fatalf("compare committed arms: %v", err)
	}
	if summary.Total != len(Catalog()) {
		t.Fatalf("compared %d probes, catalog has %d", summary.Total, len(Catalog()))
	}
	if summary.Divergent != 0 {
		t.Fatalf("behavioral divergence against the real Java oracle on %d probe(s): %v",
			summary.Divergent, summary.DivergentIDs)
	}
	for _, comparison := range summary.Comparisons {
		for _, path := range comparison.DiffPaths {
			if path != DetailField {
				t.Fatalf("%s: unexpected differing path %q (only %s may differ)",
					comparison.RequestID, path, DetailField)
			}
		}
	}
}

// TestEveryProbeHasBothArms proves the set is complete: no probe may be
// committed without a recorded result from each side.
func TestEveryProbeHasBothArms(t *testing.T) {
	java, _, err := LoadTranscript(evidencePath(t, JavaArmFile))
	if err != nil {
		t.Fatal(err)
	}
	rust, _, err := LoadTranscript(evidencePath(t, RustArmFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, probe := range Catalog() {
		if _, ok := java[probe.ID]; !ok {
			t.Fatalf("%s has no recorded Java arm", probe.ID)
		}
		if _, ok := rust[probe.ID]; !ok {
			t.Fatalf("%s has no recorded Rust arm", probe.ID)
		}
	}
}

// TestArmsAnswerTheCommittedRequests proves each arm answered the exact probe
// it claims to: every response must echo the request_digest the catalog binds.
// Without this a transcript recorded against edited requests could be committed
// alongside unedited requests.
func TestArmsAnswerTheCommittedRequests(t *testing.T) {
	for _, file := range []string{JavaArmFile, RustArmFile} {
		responses, _, err := LoadTranscript(evidencePath(t, file))
		if err != nil {
			t.Fatal(err)
		}
		for _, probe := range Catalog() {
			request, err := RequestObject(probe)
			if err != nil {
				t.Fatal(err)
			}
			want, _ := request["request_digest"].(string)
			got, _ := responses[probe.ID]["request_digest"].(string)
			if got != want {
				t.Fatalf("%s in %s echoes request_digest %s, catalog binds %s",
					probe.ID, file, got, want)
			}
		}
	}
}

// TestManifestMatchesTheCommittedArtifacts proves the manifest is not stale:
// its recorded digests must match the files beside it, and its per-probe
// verdicts must match a fresh comparison of the two arms.
func TestManifestMatchesTheCommittedArtifacts(t *testing.T) {
	raw, err := os.ReadFile(evidencePath(t, ManifestFile))
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	for name, want := range manifest.Artifacts {
		data, err := os.ReadFile(filepath.Join(repoRoot(t), EvidenceDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if got := corpora.DigestSHA256(data); got != want {
			t.Fatalf("%s digest %s, manifest records %s", name, got, want)
		}
	}
	if manifest.Counts["probes"] != len(Catalog()) {
		t.Fatalf("manifest records %d probes, catalog has %d",
			manifest.Counts["probes"], len(Catalog()))
	}
	if manifest.Counts["behaviorally_divergent"] != 0 {
		t.Fatalf("manifest records %d behavioral divergences",
			manifest.Counts["behaviorally_divergent"])
	}
	java, _, err := LoadTranscript(evidencePath(t, JavaArmFile))
	if err != nil {
		t.Fatal(err)
	}
	rust, _, err := LoadTranscript(evidencePath(t, RustArmFile))
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]ProbeRecord{}
	for _, record := range manifest.Probes {
		byID[record.RequestID] = record
	}
	for _, probe := range Catalog() {
		record, ok := byID[probe.ID]
		if !ok {
			t.Fatalf("manifest has no record for %s", probe.ID)
		}
		if record.Origin != probe.Origin || record.Class != probe.Class {
			t.Fatalf("%s: manifest records class=%s origin=%s, catalog says class=%s origin=%s",
				probe.ID, record.Class, record.Origin, probe.Class, probe.Origin)
		}
		fresh := CompareResponses(java[probe.ID], rust[probe.ID])
		if fresh.Verdict != record.Verdict {
			t.Fatalf("%s: manifest verdict %s, fresh comparison %s",
				probe.ID, record.Verdict, fresh.Verdict)
		}
		if !record.Agree {
			t.Fatalf("%s: manifest records non-agreement", probe.ID)
		}
	}
}

// armViewFieldNames enumerates every ArmView field reflectively. The provenance
// guard iterates THIS rather than a hand-written list, so a field added to
// ArmView is covered automatically. A hand-written list previously omitted
// error_code, close_code and frames, which is exactly how a weakened guard goes
// unnoticed.
func armViewFieldNames() []string {
	shape := reflect.TypeOf(ArmView{})
	names := make([]string, 0, shape.NumField())
	for i := 0; i < shape.NumField(); i++ {
		names = append(names, shape.Field(i).Name)
	}
	return names
}

func armViewField(view ArmView, name string) any {
	return reflect.ValueOf(view).FieldByName(name).Interface()
}

// TestArmViewFieldCoverageIsComplete fails if ArmView gains a field that the
// guard's expectations were not updated for. It pins the CURRENT field set, so
// adding a field is a deliberate act that forces a look at the guard.
func TestArmViewFieldCoverageIsComplete(t *testing.T) {
	want := []string{
		"Outcome", "ErrorCode", "CloseCode", "ConsumedBytes",
		"InputBytes", "Frames", "FinalState",
		"RuntimeArtifact", "RuntimeSHA256",
	}
	got := armViewFieldNames()
	if len(got) != len(want) {
		t.Fatalf("ArmView has %d fields %v, guard expects %d %v; update the guard deliberately",
			len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ArmView field %d is %q, expected %q", i, got[i], want[i])
		}
	}
}

// TestJavaArmCarriesThePinnedOracleAttestation is the PROVENANCE guard. It is
// the reason a two-arm differential means anything: without it, "Java and Rust
// agree" degenerates to "Rust agrees with itself".
//
// Every response in the Java arm must carry the pinned Java-WebSocket runtime
// attestation, and none may carry the Rust harness identity. The java-oracle
// adapter re-hashes the jar that supplied Draft_6455 at startup and refuses to
// start (exit 78) on mismatch, so this identity is emitted only by a process
// that loaded and self-verified the pinned runtime.
//
// WHAT THIS PROVES: a Rust arm copied into the Java arm is refused, because the
// harness emits its own executable digest and cannot emit the pinned runtime
// identity.
//
// WHAT THIS DOES NOT PROVE: it does not defeat an editor who also rewrites the
// runtime object. No in-repo test can, because the file is the evidence. It
// raises forgery from "copy one file" to "copy and then forge the attestation
// on every line", and it is stated here rather than overclaimed.
func TestJavaArmCarriesThePinnedOracleAttestation(t *testing.T) {
	java, order, err := LoadTranscript(evidencePath(t, JavaArmFile))
	if err != nil {
		t.Fatal(err)
	}
	if len(order) == 0 {
		t.Fatal("Java arm is empty")
	}
	for _, id := range order {
		runtimeObject, ok := java[id][RuntimeField].(map[string]any)
		if !ok {
			t.Fatalf("%s: Java arm response has no runtime attestation; it cannot be shown to be a Java observation", id)
		}
		artifact, _ := runtimeObject["artifact"].(string)
		digest, _ := runtimeObject["sha256"].(string)
		if artifact == HarnessRuntimeArtifact {
			t.Fatalf("%s: Java arm carries the RUST HARNESS attestation %q — this is a copied Rust arm, not a Java observation",
				id, artifact)
		}
		if artifact != PinnedJavaRuntimeArtifact {
			t.Fatalf("%s: Java arm attests artifact %q, expected the pinned oracle %q",
				id, artifact, PinnedJavaRuntimeArtifact)
		}
		if digest != PinnedJavaRuntimeSHA256 {
			t.Fatalf("%s: Java arm attests runtime digest %q, expected the pinned %q",
				id, digest, PinnedJavaRuntimeSHA256)
		}
	}
}

// TestRustArmCarriesTheHarnessAttestation is the mirror: the Rust arm must be
// the harness, so the two arms are provably different producers rather than one
// producer recorded twice.
func TestRustArmCarriesTheHarnessAttestation(t *testing.T) {
	rust, order, err := LoadTranscript(evidencePath(t, RustArmFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range order {
		runtimeObject, ok := rust[id][RuntimeField].(map[string]any)
		if !ok {
			t.Fatalf("%s: Rust arm response has no runtime attestation", id)
		}
		artifact, _ := runtimeObject["artifact"].(string)
		if artifact != HarnessRuntimeArtifact {
			t.Fatalf("%s: Rust arm attests artifact %q, expected %q",
				id, artifact, HarnessRuntimeArtifact)
		}
	}
}

// TestArmsAreDistinctProducers proves the two arms were produced by different
// runtimes. If both arms ever attest the same artifact, one was copied from the
// other and the differential is vacuous.
func TestArmsAreDistinctProducers(t *testing.T) {
	java, order, err := LoadTranscript(evidencePath(t, JavaArmFile))
	if err != nil {
		t.Fatal(err)
	}
	rust, _, err := LoadTranscript(evidencePath(t, RustArmFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range order {
		javaView := armView(java[id])
		rustView := armView(rust[id])
		if javaView.RuntimeArtifact == rustView.RuntimeArtifact {
			t.Fatalf("%s: both arms attest the same producer %v — the differential is vacuous",
				id, javaView.RuntimeArtifact)
		}
	}
}

// RustDetailTemplatePrefix is the wording the ws_core harness emits for every
// error diagnostic. The real Java-WebSocket runtime emits its own exception
// messages ("bad rsv RSV1: ...", "only a close frame may be received in CLOSING
// state"), which look nothing like this.
const RustDetailTemplatePrefix = "ws_core reported"

// TestJavaArmDiagnosticsAreJavaNotHarness is defence in depth behind the
// attestation guard, and it is what catches the HARDER attack: an adversary who
// copies the Rust arm AND forges the runtime attestation on every line.
//
// Two genuinely different implementations do not produce identical free-text
// diagnostics. The Java arm must carry the runtime's own exception wording, and
// must never carry the harness template. An arm that is identical to the Rust
// arm right down to the diagnostic prose was copied, not observed.
//
// To defeat this an adversary must hand-forge a plausible Java-WebSocket
// diagnostic for every error case — that is fabricating the upstream library's
// internal messages, not copying a file.
func TestJavaArmDiagnosticsAreJavaNotHarness(t *testing.T) {
	java, order, err := LoadTranscript(evidencePath(t, JavaArmFile))
	if err != nil {
		t.Fatal(err)
	}
	rust, _, err := LoadTranscript(evidencePath(t, RustArmFile))
	if err != nil {
		t.Fatal(err)
	}
	errorCases := 0
	for _, id := range order {
		javaError, ok := java[id]["error"].(map[string]any)
		if !ok {
			continue
		}
		errorCases++
		javaDetail, _ := javaError["detail"].(string)
		if javaDetail == "" {
			t.Fatalf("%s: Java arm error has no detail wording", id)
		}
		if strings.HasPrefix(javaDetail, RustDetailTemplatePrefix) {
			t.Fatalf("%s: Java arm diagnostic %q uses the ws_core harness template — this is harness output, not a Java observation",
				id, javaDetail)
		}
		rustError, ok := rust[id]["error"].(map[string]any)
		if !ok {
			t.Fatalf("%s: Rust arm has no error object where Java does", id)
		}
		rustDetail, _ := rustError["detail"].(string)
		if javaDetail == rustDetail {
			t.Fatalf("%s: both arms emit the identical diagnostic %q; two different implementations do not produce identical free text, so one arm was copied",
				id, javaDetail)
		}
	}
	if errorCases == 0 {
		t.Fatal("no error-outcome probes found; this guard would be vacuous")
	}
	// Pin the count so the guard cannot quietly become near-vacuous if the
	// error probes are removed.
	if errorCases != 17 {
		t.Fatalf("expected 17 error-outcome probes to guard, found %d; update deliberately", errorCases)
	}
}

// TestManifestJavaArmMatchesTheRecordedTranscript proves the manifest's
// Java-side values were projected from the recorded Java transcript and not
// copied from the Rust arm. It compares EVERY ArmView field, enumerated
// reflectively, including the runtime attestation.
//
// Note the division of labour: this test binds MANIFEST to FILE.
// TestJavaArmCarriesThePinnedOracleAttestation binds FILE to PRODUCER. Both are
// needed; the first alone is satisfied by a copied arm with a regenerated
// manifest, which is precisely the hole this round closed.
func TestManifestJavaArmMatchesTheRecordedTranscript(t *testing.T) {
	raw, err := os.ReadFile(evidencePath(t, ManifestFile))
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	java, _, err := LoadTranscript(evidencePath(t, JavaArmFile))
	if err != nil {
		t.Fatal(err)
	}
	rust, _, err := LoadTranscript(evidencePath(t, RustArmFile))
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Probes) == 0 {
		t.Fatal("manifest records no probes")
	}
	for _, record := range manifest.Probes {
		wantJava := armView(java[record.RequestID])
		wantRust := armView(rust[record.RequestID])
		for _, field := range armViewFieldNames() {
			if !sameJSONScalar(armViewField(record.Java, field), armViewField(wantJava, field)) {
				t.Fatalf("%s: manifest java %s = %v, Java transcript = %v",
					record.RequestID, field,
					armViewField(record.Java, field), armViewField(wantJava, field))
			}
			if !sameJSONScalar(armViewField(record.Rust, field), armViewField(wantRust, field)) {
				t.Fatalf("%s: manifest rust %s = %v, Rust transcript = %v",
					record.RequestID, field,
					armViewField(record.Rust, field), armViewField(wantRust, field))
			}
		}
		// The manifest's own Java column must attest the pinned oracle, so a
		// forged manifest cannot claim a Java observation either.
		if record.Java.RuntimeArtifact != PinnedJavaRuntimeArtifact {
			t.Fatalf("%s: manifest java column attests %v, expected the pinned oracle %q",
				record.RequestID, record.Java.RuntimeArtifact, PinnedJavaRuntimeArtifact)
		}
	}
}

// sameJSONScalar compares values that may arrive as json.Number (from the
// transcript loader) or float64/string (from encoding/json on the manifest).
func sameJSONScalar(a, b any) bool {
	return scalarText(a) == scalarText(b)
}

func scalarText(v any) string {
	switch typed := v.(type) {
	case nil:
		return "null"
	case json.Number:
		return typed.String()
	case float64:
		return json.Number(trimFloat(typed)).String()
	case string:
		return typed
	default:
		data, _ := json.Marshal(typed)
		return string(data)
	}
}

func trimFloat(f float64) string {
	data, _ := json.Marshal(f)
	return string(data)
}
