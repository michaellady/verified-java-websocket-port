package normcollide

import (
	"regexp"
	"strings"
	"testing"
)

// TestLandingRecordStatesTheBoundsTheDocumentMeasures is the pin the prose never
// had. It runs in the DEFAULT suite — no harness, no build tag — because both
// inputs are committed files, and a drift gate that only fires under a tag is a
// drift gate that does not fire.
//
// It is the check that would have caught d90308a moving the handshake bounds
// from 26/27/11 to 29/23/10 while drafts/self-review/normalization-collision-audit.md
// went on stating the old three as present tense.
func TestLandingRecordStatesTheBoundsTheDocumentMeasures(t *testing.T) {
	mismatches, err := CheckRecordBounds(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(mismatches) == 0 {
		return
	}
	var report strings.Builder
	for _, m := range mismatches {
		report.WriteString("\n  " + m.String())
	}
	t.Fatalf("the landing record and the committed document disagree on %d bound(s).\n"+
		"The document is recomputed from a real harness run and refused when stale, so "+
		"the prose is what is wrong. Restate the record; do not relax this check.%s",
		len(mismatches), report.String())
}

// TestRecordBoundCheckFailsClosedWhenAClaimIsMissing is the probe that
// distinguishes this check from its negation. A check that passed when the
// sentence was absent would be defeated by deleting the sentence — the cheapest
// possible way to stop a number being stale — so absence must read as failure.
func TestRecordBoundCheckFailsClosedWhenAClaimIsMissing(t *testing.T) {
	claim := BoundClaim{
		Field:   "synthetic",
		Pattern: regexp.MustCompile(`this sentence appears in no record (\d+)`),
		Want:    func(*Document) int { return 29 },
	}
	flat, _ := flattenRecord("a record that does not carry the claim")
	if claim.Pattern.FindStringSubmatchIndex(flat) != nil {
		t.Fatal("the synthetic claim matched; the fixture no longer demonstrates absence")
	}
	m := BoundMismatch{Field: claim.Field, Found: boundClaimAbsent, Want: 29}
	if !strings.Contains(m.String(), "no longer states this bound") {
		t.Fatalf("an absent claim does not report as absent: %s", m.String())
	}
}

// TestFlattenRecordJoinsAWrappedSentenceAndStripsEmphasis pins the two
// properties the matcher depends on. Without the first, every bound the author
// wrapped across a line break reads as ABSENT and the check becomes noise;
// without the second, adding two asterisks defeats it.
func TestFlattenRecordJoinsAWrappedSentenceAndStripsEmphasis(t *testing.T) {
	flat, lineOf := flattenRecord("- The 49 handshake cases produce only **29\ndistinct scored observations**.")
	const want = "- The 49 handshake cases produce only 29 distinct scored observations."
	if flat != want {
		t.Fatalf("flatten gave %q, want %q", flat, want)
	}
	pattern := regexp.MustCompile(`49 handshake cases produce only (\d+) distinct scored observations`)
	location := pattern.FindStringSubmatchIndex(flat)
	if location == nil {
		t.Fatal("the wrapped sentence did not match after flattening")
	}
	if got := flat[location[2]:location[3]]; got != "29" {
		t.Fatalf("captured %q, want 29", got)
	}
	if lineOf[location[0]] != 1 {
		t.Fatalf("match reported on line %d, want 1", lineOf[location[0]])
	}
	// Underscores must SURVIVE flattening. Stripping them as markdown emphasis
	// turned sec_websocket_accept into secwebsocketaccept, so the surface-row
	// check reported a correct row as missing every scored key it named. The
	// bug was found by that check failing on a row already fixed by hand.
	kept, _ := flattenRecord("names `sec_websocket_accept` and `reject_stage`")
	if !strings.Contains(kept, "sec_websocket_accept") || !strings.Contains(kept, "reject_stage") {
		t.Fatalf("flatten mangled an identifier: %q", kept)
	}
}

// TestEveryBoundClaimCapturesExactlyOneNumber refuses a claim whose pattern has
// no capture group or more than one: CheckRecordBounds indexes group 1 and
// would panic or read the wrong number, and a bad pattern must be caught here
// rather than by a nil deref during a gate run.
func TestEveryBoundClaimCapturesExactlyOneNumber(t *testing.T) {
	claims := RecordBoundClaims()
	if len(claims) == 0 {
		t.Fatal("no bound claims: the check would pass by having nothing to check")
	}
	for _, claim := range claims {
		if n := claim.Pattern.NumSubexp(); n != 1 {
			t.Errorf("%s: pattern has %d capture groups, want exactly 1", claim.Field, n)
		}
		if claim.Want == nil {
			t.Errorf("%s: no Want reader", claim.Field)
		}
	}
}

// TestLandingRecordSurfaceRowNamesWhatTheDocumentScores pins the two axes
// PartitionCensus cannot reach — how many keys each handshake shape has, and
// which scored keys discriminate — on the one row that demonstrably rotted.
func TestLandingRecordSurfaceRowNamesWhatTheDocumentScores(t *testing.T) {
	mismatches, err := CheckRecordSurfaceRow(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(mismatches) == 0 {
		return
	}
	var report strings.Builder
	for _, m := range mismatches {
		report.WriteString("\n  " + m.String())
	}
	t.Fatalf("the landing record's handshake.judged row disagrees with the committed "+
		"document on %d point(s). PartitionCensus cannot catch this: "+
		"ClassifyHandshakeKeys returns handshake.judged for ANY key set containing "+
		"java_observable, so the shape stays classified while the row rots.%s",
		len(mismatches), report.String())
}
