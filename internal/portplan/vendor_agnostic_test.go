package portplan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The owner ruled the reproduction check vendor-agnostic: `jdk_vendor` is the
// compiling JDK build's `java.vendor` ("Homebrew" for the macOS bottle the
// report was committed from, "Eclipse Adoptium" for the same 17.0.19+10 on
// Linux), which is host provenance rather than semantic identity. These tests
// hold the ruling to its stated bar: that ONE field is excluded, and EVERY other
// difference is still caught.

func committedOracleBytes(t *testing.T) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(repoRoot, EvidenceDirectory, OracleEvidenceDocument))
	if err != nil {
		t.Fatalf("read committed oracle: %v", err)
	}
	return content
}

// Direction 1: a report differing ONLY in the vendor line compares equal.
func TestVendorOnlyDifferenceCompareEqualAfterNeutralization(t *testing.T) {
	committed := committedOracleBytes(t)
	regenerated := []byte(strings.Replace(string(committed),
		`"jdk_vendor": "Homebrew"`, `"jdk_vendor": "Eclipse Adoptium"`, 1))
	if string(regenerated) == string(committed) {
		t.Fatal("fixture assumption broken: no jdk_vendor line to alter")
	}

	committedNormalized, committedVendor, committedCount := neutralizeJDKVendor(committed)
	regeneratedNormalized, regeneratedVendor, regeneratedCount := neutralizeJDKVendor(regenerated)

	if committedCount != 1 || regeneratedCount != 1 {
		t.Fatalf("exactly one vendor line must be found in each report, got %d and %d",
			committedCount, regeneratedCount)
	}
	if committedVendor != "Homebrew" || regeneratedVendor != "Eclipse Adoptium" {
		t.Fatalf("the excluded value must still be READ so the message can name it;"+
			" got committed %q regenerated %q", committedVendor, regeneratedVendor)
	}
	if string(committedNormalized) != string(regeneratedNormalized) {
		t.Fatalf("a vendor-only difference must compare equal:\n%s",
			describeOracleMismatch(regeneratedNormalized, committedNormalized, "oracle.json"))
	}
}

// Direction 2, and the whole point of the bar: changing ANY other single line
// must still fail, and the message must name what differed. A declaration line
// is the case the exclusion must not have widened into.
func TestAnyOtherSingleLineDifferenceIsStillCaught(t *testing.T) {
	committed := committedOracleBytes(t)

	// One of the 969 declaration lines, altered in one field.
	const originalDeclarationFragment = `"semantic_key": "org.java_websocket.WebSocket#close()V"`
	const alteredDeclarationFragment = `"semantic_key": "org.java_websocket.WebSocket#close()Z"`
	if !strings.Contains(string(committed), originalDeclarationFragment) {
		t.Fatalf("fixture assumption broken: %s absent from the committed oracle",
			originalDeclarationFragment)
	}
	// Vendor differs too, so this proves the vendor exclusion did not swallow the
	// declaration difference sitting beside it.
	regenerated := strings.Replace(string(committed),
		`"jdk_vendor": "Homebrew"`, `"jdk_vendor": "Eclipse Adoptium"`, 1)
	regenerated = strings.Replace(regenerated,
		originalDeclarationFragment, alteredDeclarationFragment, 1)

	committedNormalized, _, _ := neutralizeJDKVendor(committed)
	regeneratedNormalized, _, _ := neutralizeJDKVendor([]byte(regenerated))
	if string(committedNormalized) == string(regeneratedNormalized) {
		t.Fatal("a declaration difference must NOT be neutralized away by the vendor exclusion")
	}
	message := describeOracleMismatch(regeneratedNormalized, committedNormalized, "oracle.json")
	if !strings.Contains(message, "differing_lines=1") {
		t.Errorf("exactly the declaration line must differ; the vendor line must not be"+
			" counted:\n%s", message)
	}
	if !strings.Contains(message, "close()Z") {
		t.Errorf("the message must name the declaration that differs:\n%s", message)
	}
	if strings.Contains(message, jdkVendorFieldName) {
		t.Errorf("the excluded field must not appear among the differences:\n%s", message)
	}
}

// Every other header field is host-adjacent too, and NONE of them is excluded.
// This is the guard against the exclusion widening from one field to "the
// provenance block".
func TestNeighbouringHeaderFieldsAreNotExcluded(t *testing.T) {
	committed := committedOracleBytes(t)
	for _, alteration := range []struct{ name, from, to string }{
		{"jdk_version", `"jdk_version": "17.0.19"`, `"jdk_version": "17.0.20"`},
		{"tool_version", `"tool_version": "1.0.0"`, `"tool_version": "1.0.1"`},
		{"declarations total", `"declarations": 969`, `"declarations": 968`},
		{"a file hash", `"physical_lines": 376`, `"physical_lines": 377`},
	} {
		if !strings.Contains(string(committed), alteration.from) {
			t.Fatalf("fixture assumption broken: %q absent", alteration.from)
		}
		altered := strings.Replace(string(committed), alteration.from, alteration.to, 1)
		committedNormalized, _, _ := neutralizeJDKVendor(committed)
		alteredNormalized, _, _ := neutralizeJDKVendor([]byte(altered))
		if string(committedNormalized) == string(alteredNormalized) {
			t.Errorf("%s is NOT excluded and a change to it must still differ", alteration.name)
		}
	}
}

// Ignoring a value is not tolerating its absence. A report with no vendor line,
// or with more than one, is one the comparison cannot reason about.
func TestVendorFieldAbsenceAndAmbiguityAreVisible(t *testing.T) {
	committed := committedOracleBytes(t)

	withoutVendor := strings.Replace(string(committed),
		"  \"jdk_vendor\": \"Homebrew\",\n", "", 1)
	if withoutVendor == string(committed) {
		t.Fatal("fixture assumption broken: could not remove the vendor line")
	}
	if _, _, count := neutralizeJDKVendor([]byte(withoutVendor)); count != 0 {
		t.Errorf("an absent vendor field must be counted as absent, got %d", count)
	}

	doubled := strings.Replace(string(committed),
		"  \"jdk_vendor\": \"Homebrew\",\n",
		"  \"jdk_vendor\": \"Homebrew\",\n  \"jdk_vendor\": \"Homebrew\",\n", 1)
	if _, _, count := neutralizeJDKVendor([]byte(doubled)); count != 2 {
		t.Errorf("a duplicated vendor field must be counted, got %d", count)
	}
}

// The matcher is line-shaped on purpose: `jdk_vendor` occurring anywhere else is
// still compared byte for byte.
func TestVendorMatcherIsLineShapedNotSubstring(t *testing.T) {
	notTheField := []byte("{\n  \"name\": \"jdk_vendor\",\n" +
		"  \"descriptor\": \"()Ljava/lang/String;\"\n}\n")
	normalized, _, count := neutralizeJDKVendor(notTheField)
	if count != 0 {
		t.Errorf("a declaration merely NAMED jdk_vendor is not the header field, got count=%d",
			count)
	}
	if string(normalized) != string(notTheField) {
		t.Errorf("nothing outside the header field may be rewritten:\n%s", normalized)
	}
}

// A vendor line that gained or lost a line around it still changes the line
// count, so the neutralization cannot hide structural drift.
func TestNeutralizationPreservesLineCount(t *testing.T) {
	committed := committedOracleBytes(t)
	normalized, _, count := neutralizeJDKVendor(committed)
	if count != 1 {
		t.Fatalf("committed oracle must carry exactly one vendor line, got %d", count)
	}
	if got, want := strings.Count(string(normalized), "\n"),
		strings.Count(string(committed), "\n"); got != want {
		t.Fatalf("neutralization changed the line count: %d vs %d", got, want)
	}
}
