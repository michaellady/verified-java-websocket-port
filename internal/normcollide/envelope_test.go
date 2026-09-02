package normcollide

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/diffregress"
)

// TestEnvelopeErrorRowsCannotEnterTheDifferentialAtAll turns the one prose
// claim in the surface table that no probe can decide into a check.
//
// The `behaviour.envelope_error` projection emits `"request_id": null` and no
// digest binding at all, so its Scorer field says NONE: a transcript carrying
// one of these cannot be loaded, let alone compared. That is an EXCLUSION, not
// a collision — and it is the honest, fail-closed outcome — but a table entry
// that says so without anything checking it is exactly the kind of comment
// this package exists to distrust.
//
// Verified independently at the command line before this test was written:
//
//	diffregressctl compare --java <two envelope-error rows> --rust <same>
//	  compare: ... line 1: response has no request_id
//	  exit status 2
func TestEnvelopeErrorRowsCannotEnterTheDifferentialAtAll(t *testing.T) {
	// The exact shape ws-oracle-harness emits for a line it cannot parse,
	// mirroring OracleMain.error. Two DIFFERENT rejections, so if the loader
	// accepted them the comparison would proceed and this test would have to
	// assert something about the result instead.
	transcript := `{"error":{"code":"UNKNOWN_FIELD","detail":"unknown field in request: nope"},` +
		`"outcome":"error","protocol":"java-websocket-oracle","request_id":null,"version":"1.0.0"}` + "\n" +
		`{"error":{"code":"INVALID_JSON","detail":"invalid literal"},` +
		`"outcome":"error","protocol":"java-websocket-oracle","request_id":null,"version":"1.0.0"}` + "\n"

	path := filepath.Join(t.TempDir(), "envelope.jsonl")
	if err := os.WriteFile(path, []byte(transcript), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := diffregress.LoadTranscript(path)
	if err == nil {
		t.Fatal("diffregress.LoadTranscript accepted a transcript whose rows carry " +
			"request_id: null. The surface table claims these rows cannot be compared at " +
			"all; if that stopped being true, behaviour.envelope_error would need a " +
			"collision probe and it has none.")
	}
	if !strings.Contains(err.Error(), "no request_id") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}

	// Positive control: the SAME loader accepts a well-formed row, so the
	// refusal above is about the null id and not about the loader being
	// broken for everything.
	good := filepath.Join(t.TempDir(), "good.jsonl")
	if err := os.WriteFile(good, []byte(
		`{"outcome":"error","request_id":"x","version":"1.0.0"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := diffregress.LoadTranscript(good); err != nil {
		t.Fatalf("LoadTranscript rejected a well-formed row: %v", err)
	}
}

// TestSurfaceTableMarksTheEnvelopeProjectionUnscored keeps the table honest
// about the test above: the entry must say the projection has no scorer, and
// must carry no compared fields.
func TestSurfaceTableMarksTheEnvelopeProjectionUnscored(t *testing.T) {
	for _, projection := range Projections() {
		if projection.ID != "behaviour.envelope_error" {
			continue
		}
		if len(projection.Scores) != 0 {
			t.Fatalf("behaviour.envelope_error claims to compare %v, but no transcript "+
				"carrying it can be loaded", projection.Scores)
		}
		if !strings.HasPrefix(projection.Scorer, "NONE") {
			t.Fatalf("behaviour.envelope_error names scorer %q; it has none", projection.Scorer)
		}
		return
	}
	t.Fatal("the surface table no longer enumerates behaviour.envelope_error")
}
