package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	gateName     = "record-content-precondition"
	selfcheckRel = "cmd/recordguardctl/testdata"
	manifestRel  = selfcheckRel + "/polarity.json"
)

// polarityCase is one committed record whose verdict is declared in advance.
type polarityCase struct {
	Path       string   `json:"path"`
	Provenance string   `json:"provenance"`
	Why        string   `json:"why"`
	Expect     []string `json:"expect"`
}

func (c polarityCase) mustFire() bool { return len(c.Expect) > 0 }

type polarityManifest struct {
	Note  string         `json:"note"`
	Cases []polarityCase `json:"cases"`
}

func loadManifest(root string) (polarityManifest, error) {
	var m polarityManifest
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(manifestRel)))
	if err != nil {
		return m, fmt.Errorf("polarity manifest unreadable at %s: %w", manifestRel, err)
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return m, fmt.Errorf("polarity manifest is not valid JSON: %w", err)
	}
	if len(m.Cases) == 0 {
		return m, fmt.Errorf("the polarity manifest declares no cases: an empty self-check proves nothing")
	}
	return m, nil
}

// selfcheck replays the discriminator over the committed historical records and
// reports whether every case came out as declared. The div05 stub that F009 was
// filed about is in there verbatim from git: if the rule ever stops firing on
// the instance that motivated it, this fails.
func selfcheck(root string, stdout, stderr io.Writer) bool {
	manifest, err := loadManifest(root)
	if err != nil {
		fmt.Fprintf(stderr, "gate=%s step=selfcheck result=FAIL error=%q\n", gateName, err.Error())
		return false
	}
	firing, silent, ok := 0, 0, true
	for _, c := range manifest.Cases {
		p := filepath.Join(root, filepath.FromSlash(selfcheckRel), filepath.FromSlash(c.Path))
		src, err := os.ReadFile(p)
		if err != nil {
			fmt.Fprintf(stderr, "gate=%s step=selfcheck case=%s result=FAIL error=%q\n", gateName, c.Path, err.Error())
			ok = false
			continue
		}
		if c.mustFire() {
			firing++
		} else {
			silent++
		}
		sigs := Scan(string(src))
		verdict := "OK"
		if diff := rowDiff(Rows(sigs), c.Expect); diff != "" {
			verdict = "POLARITY-FAIL"
			ok = false
			fmt.Fprintf(stderr, "gate=%s step=selfcheck case=%s POLARITY-FAIL %s\n", gateName, c.Path, diff)
		}
		fmt.Fprintf(stdout, "gate=%s step=selfcheck case=%s expect=%d found=%d lines=%d result=%s provenance=%q\n",
			gateName, c.Path, len(c.Expect), len(sigs), strings.Count(string(src), "\n"), verdict, c.Provenance)
		// Print WHAT fired and the sentence it was read from, so the gate log
		// is itself the historical proof rather than a bare count.
		for _, s := range sigs {
			fmt.Fprintf(stdout, "    fires line=%d signal=%s term=%q | %s\n", s.Line, s.Kind, s.Term, s.Text)
		}
	}
	if firing == 0 || silent == 0 {
		fmt.Fprintf(stderr, "gate=%s step=selfcheck result=FAIL error=%q\n", gateName,
			fmt.Sprintf("the self-check needs both polarities to mean anything: %d firing case(s), %d silent case(s)", firing, silent))
		ok = false
	}
	verdict := "PASS"
	if !ok {
		verdict = "FAIL"
	}
	fmt.Fprintf(stdout, "gate=%s step=selfcheck cases=%d firing=%d silent=%d result=%s\n",
		gateName, len(manifest.Cases), firing, silent, verdict)
	return ok
}

func rowDiff(got, want []string) string {
	if want == nil {
		want = []string{}
	}
	if len(got) == len(want) {
		same := true
		for i := range got {
			if got[i] != want[i] {
				same = false
				break
			}
		}
		if same {
			return ""
		}
	}
	return fmt.Sprintf("declared %v, observed %v", want, got)
}
