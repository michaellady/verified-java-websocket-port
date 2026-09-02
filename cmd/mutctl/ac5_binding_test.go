package main

import (
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/ac5class"
)

// TestAC5RegisterCampaignBindingHolds keeps the US-020 AC5 class register
// (internal/ac5class) and this campaign's curated table honest about each
// other.
//
// The register marks each seeded variant with InE1Campaign: true when the
// E1 ws-core campaign also judges it. That claim is worth exactly as much as
// a check on it:
//
//   - a variant claiming to be in the campaign must be a row of
//     CuratedMutations with the SAME file, occurrence and literals, so the two
//     tables cannot drift into describing different defects under one id; and
//   - a variant NOT claiming it must be absent, so nobody can quietly inherit
//     the campaign's evidence for a seed the campaign never ran.
//
// The second half matters more than it looks. Five of the register's seven
// classes are seeded by variants this campaign does NOT run — they are judged
// by `ac5ctl run` against its own receipt — and the failure this whole track
// exists to prevent is exactly that kind of borrowed credit.
func TestAC5RegisterCampaignBindingHolds(t *testing.T) {
	curated := map[string]Mutation{}
	for _, m := range CuratedMutations() {
		curated[m.ID] = m
	}
	claimed, unclaimed := 0, 0
	for _, v := range ac5class.Register() {
		m, present := curated[v.ID]
		if v.InE1Campaign {
			claimed++
			if !present {
				t.Errorf("%s (class %q) claims InE1Campaign and is not a row of CuratedMutations",
					v.ID, v.Class)
				continue
			}
			if m.File != v.File || m.Match != v.Match || m.Replace != v.Replace ||
				normalizeOccurrence(m.Occurrence) != normalizeOccurrence(v.Occurrence) {
				t.Errorf("%s: the register and the curated table describe DIFFERENT defects under "+
					"one id (file %q vs %q, occurrence %d vs %d, literals equal: match=%v replace=%v)",
					v.ID, v.File, m.File, normalizeOccurrence(v.Occurrence),
					normalizeOccurrence(m.Occurrence), m.Match == v.Match, m.Replace == v.Replace)
			}
			continue
		}
		unclaimed++
		if present {
			t.Errorf("%s (class %q) does NOT claim InE1Campaign yet is a row of CuratedMutations: "+
				"either the claim or the row is wrong", v.ID, v.Class)
		}
	}
	if claimed == 0 {
		t.Error("no register variant claims E1 campaign coverage: the binding this test guards is empty")
	}
	if unclaimed == 0 {
		t.Error("every register variant claims E1 campaign coverage, so the second half of this " +
			"test can never fire; if that is genuinely true the register should say so deliberately")
	}
}

func normalizeOccurrence(n int) int {
	if n < 1 {
		return 1
	}
	return n
}
