// recordguardctl refuses to let a drafts/self-review record satisfy a landing
// precondition while the record still says it is unfinished.
//
// WHY THIS EXISTS. F009 records that three wave-4 branches were judged complete
// by running `git log --oneline` and a COUNT of files matching
// `drafts/self-review`, and reported to the owner as "each ends with a
// self-review record". Two of the three did. `claude/div05-close-overtakes-echo`
// carried a nine-line stub — "STATUS: IN PROGRESS … Nothing verified yet" —
// behind seven commits and 983 insertions of finished-looking code, with no Java
// citation, no RED reading, no differential and no deletion attack. Landing it
// would have put an unreviewed behaviour-bearing change on mainline. It was
// caught only because someone opened the file. F009 names the rule in one line —
// A RECORD IS READ FOR ITS CONTENT, NEVER COUNTED FOR ITS PRESENCE — and files
// the mechanical version as worth building and not built. This is that.
//
// WHAT IT CLAIMS. Five signals, defined in scan.go, all of which READ the
// record's text: the record's own status declaration, its title qualifier, a
// void self-report ("nothing verified yet"), an open markdown checklist, and
// citing nothing whatsoever. It does NOT claim to detect a record that is
// substantively wrong, thin, or dishonest while presenting itself as finished;
// see drafts/self-review/record-content-precondition.md for the full list of
// errors this rule knowingly makes in both directions.
//
// WHERE IT BINDS, AND WHY THE TWO MODES DIFFER. A record that says IN PROGRESS
// while genuinely in progress is CORRECT — this repository's own discipline
// tells agents to push a stub in their first few tool calls so a container
// restart cannot lose the branch. The failure is landing on such a record, not
// writing one. So the refusal lives at the decision point:
//
//	recordguardctl precondition <record>...   exit 1 if any named record is unfinished
//
// invoked by GOAL-LOOP.md step 6 before a `merge: <branch>` commit is made. The
// gate mode carries NO ceiling on unfinished records in the tree, deliberately:
// a ceiling would gate against the stub-pushing discipline the loop mandates.
// What the gate does instead is keep the refusal ALIVE —
//
//	recordguardctl gate    exit 1 if the discriminator no longer comes out as declared
//
// replaying it over committed historical records whose verdicts are declared in
// testdata/polarity.json, and printing a census of the working tree so that
// honestly-unfinished records are VISIBLE without being punished.
//
// HONESTY CONTRACT. The tool prints what it actually looked at — records read,
// lines read, the sentence each signal was read from — and FAILS if it read
// nothing, because a scanner that matched nothing and reported PASS is theatre.
package main

import (
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// recordsRel is the tree the census walks.
const recordsRel = "drafts/self-review"

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func usage(stderr io.Writer) int {
	fmt.Fprint(stderr, `recordguardctl — read a self-review record for its content, never count it for its presence

  recordguardctl precondition [-root DIR] <record-path>...
      The landing decision point. Reads each named record and exits 1 if any of
      them still says it is unfinished. Exits 0 only when every named record
      reads as finished. A record that does not exist is a refusal, not a pass.

  recordguardctl gate [-root DIR] [-no-selfcheck]
      Replays the discriminator over the committed historical records in
      cmd/recordguardctl/testdata and exits 1 if any came out other than
      declared, then prints a census of `+recordsRel+` without failing on it.
`)
	return 2
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return usage(stderr)
	}
	switch args[0] {
	case "precondition":
		return runPrecondition(args[1:], stdout, stderr)
	case "gate":
		return runGate(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "recordguardctl: unknown mode %q\n", args[0])
		return usage(stderr)
	}
}

// runPrecondition is the refusal. It is what a landing decision runs.
func runPrecondition(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("precondition", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "repository root")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() == 0 {
		fmt.Fprintf(stderr, "gate=%s mode=precondition result=FAIL reason=%q\n", gateName,
			"no record named: a landing precondition with no record to read is the defect this tool exists to refuse")
		return 2
	}
	refused := 0
	for _, rel := range flags.Args() {
		rel = filepath.ToSlash(rel)
		p := filepath.Join(*root, filepath.FromSlash(rel))
		data, err := os.ReadFile(p)
		if err != nil {
			fmt.Fprintf(stderr, "gate=%s mode=precondition record=%s verdict=REFUSED reason=%q\n",
				gateName, rel, fmt.Sprintf("unreadable: %v", err))
			refused++
			continue
		}
		sigs := Scan(string(data))
		lines := strings.Count(string(data), "\n") + 1
		if len(sigs) == 0 {
			fmt.Fprintf(stdout, "gate=%s mode=precondition record=%s lines=%d signals=0 verdict=READS-FINISHED\n",
				gateName, rel, lines)
			continue
		}
		refused++
		// A superseded record is STILL refused as a landing precondition — a
		// landing decision must never name a withdrawn document as its review.
		// But the reason differs, and saying so is the point: the fix is to name
		// the superseding record, not to go and finish this one.
		if target, ok, why := Supersession(p); ok {
			fmt.Fprintf(stdout, "gate=%s mode=precondition record=%s lines=%d signals=%d verdict=REFUSED-SUPERSEDED superseded_by=%s\n",
				gateName, rel, lines, len(sigs), filepath.ToSlash(target))
			fmt.Fprintf(stdout, "      this record declares itself superseded and the claim CHECKS OUT: %s exists and itself reads finished. It is deliberately retained, not unfinished work. Name the superseding record instead of finishing this one.\n",
				filepath.ToSlash(target))
			continue
		} else if why != "" {
			// The record claims supersession and the claim does NOT hold. This
			// is louder than a plain unfinished verdict, not quieter: an
			// unverifiable withdrawal is how a stub would escape if the claim
			// were taken on trust.
			fmt.Fprintf(stdout, "gate=%s mode=precondition record=%s lines=%d signals=%d verdict=REFUSED superseded_by_claim=%s claim_fails=%q\n",
				gateName, rel, lines, len(sigs), filepath.ToSlash(target), why)
			fmt.Fprintf(stdout, "      the record declares itself superseded, and the claim DOES NOT CHECK OUT: %s. A supersession that cannot be resolved is not a supersession; fix the path or finish the record.\n", why)
			for _, sg := range sigs {
				fmt.Fprintf(stdout, "    line=%d signal=%s term=%q | %s\n", sg.Line, sg.Kind, sg.Term, sg.Text)
			}
			continue
		}
		fmt.Fprintf(stdout, "gate=%s mode=precondition record=%s lines=%d signals=%d verdict=REFUSED\n",
			gateName, rel, lines, len(sigs))
		for _, s := range sigs {
			fmt.Fprintf(stdout, "    line=%d signal=%s term=%q | %s\n", s.Line, s.Kind, s.Term, s.Text)
			fmt.Fprintf(stdout, "      %s\n", explain(s))
		}
	}
	if refused > 0 {
		fmt.Fprintf(stderr, "gate=%s mode=precondition result=FAIL reason=%q\n", gateName,
			fmt.Sprintf("%d of %d named record(s) do not read as finished: the branch is UNREVIEWED until its record says what it did", refused, flags.NArg()))
		return 1
	}
	fmt.Fprintf(stdout, "gate=%s mode=precondition records=%d result=PASS\n", gateName, flags.NArg())
	return 0
}

// runGate keeps the refusal alive. It does NOT refuse unfinished records in the
// tree — see the package comment for why that would be wrong.
func runGate(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("gate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "repository root")
	skipSelfcheck := flags.Bool("no-selfcheck", false, "skip the polarity self-check (for debugging only; the gate never sets it)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "recordguardctl gate: unexpected argument %q\n", flags.Arg(0))
		return 2
	}

	ok := true
	if *skipSelfcheck {
		fmt.Fprintf(stdout, "gate=%s step=selfcheck result=SKIPPED note=%q\n", gateName,
			"-no-selfcheck was passed: this run makes no claim that the discriminator still fires on the div05 stub")
	} else if !selfcheck(*root, stdout, stderr) {
		ok = false
	}

	records, unfinished, err := census(*root)
	if err != nil {
		fmt.Fprintf(stderr, "gate=%s step=census result=FAIL error=%v\n", gateName, err)
		return 1
	}
	superseded := 0
	for _, u := range unfinished {
		if target, ok, _ := Supersession(filepath.Join(*root, filepath.FromSlash(u.rel))); ok {
			superseded++
			fmt.Fprintf(stdout, "gate=%s census SUPERSEDED record=%s signals=%d superseded_by=%s\n",
				gateName, u.rel, len(u.sigs), filepath.ToSlash(target))
			fmt.Fprintf(stdout, "    not unfinished work: the record says it was replaced, and the named record exists and reads finished. Retained on purpose.\n")
			continue
		}
		fmt.Fprintf(stdout, "gate=%s census UNFINISHED record=%s signals=%d first=%s@%d\n",
			gateName, u.rel, len(u.sigs), u.sigs[0].Kind, u.sigs[0].Line)
		fmt.Fprintf(stdout, "    %s\n", u.sigs[0].Text)
		fmt.Fprintf(stdout, "    not a gate failure: an honestly-unfinished record is CORRECT. It is refused only when a landing decision names it.\n")
	}
	fmt.Fprintf(stdout, "gate=%s step=census records=%d unfinished=%d superseded=%d finished=%d\n",
		gateName, records, len(unfinished)-superseded, superseded, records-len(unfinished))

	if records == 0 {
		fmt.Fprintf(stderr, "gate=%s step=census result=FAIL reason=%q\n", gateName,
			"the census read no records at all: a detector that looked at nothing is not evidence")
		ok = false
	}
	if !ok {
		return 1
	}
	fmt.Fprintf(stdout, "gate=%s result=PASS\n", gateName)
	return 0
}

type censusRow struct {
	rel  string
	sigs []Signal
}

// census reads every record in drafts/self-review and reports which ones say
// they are unfinished. It reports; it does not refuse.
func census(root string) (int, []censusRow, error) {
	dir := filepath.Join(root, filepath.FromSlash(recordsRel))
	if _, err := os.Stat(dir); err != nil {
		return 0, nil, fmt.Errorf("record tree not found at %s: %w", recordsRel, err)
	}
	total := 0
	var rows []censusRow
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".md") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		total++
		if sigs := Scan(string(data)); len(sigs) > 0 {
			rows = append(rows, censusRow{rel: filepath.ToSlash(rel), sigs: sigs})
		}
		return nil
	})
	sort.Slice(rows, func(i, j int) bool { return rows[i].rel < rows[j].rel })
	return total, rows, err
}

func explain(s Signal) string {
	switch s.Kind {
	case "declared-status":
		return fmt.Sprintf("the record's own status declaration reads %q. It is saying, in its own voice, that it is not done; "+
			"a landing decision that treats it as a completed review is reading the file's existence, not its content.", s.Term)
	case "declared-title":
		return fmt.Sprintf("the record's title qualifies itself as %q. Working notes are not a review record; "+
			"the branch's landing record is a different file, or does not exist yet.", s.Term)
	case "void-self-report":
		return fmt.Sprintf("the record reports, in its own voice, that it holds no results: %q. "+
			"There is nothing here for a landing decision to rest on.", s.Term)
	case "open-checklist":
		return fmt.Sprintf("the record carries an unchecked task box, %q. The record itself says this item is not done.", s.Term)
	case "cites-nothing":
		return "the record cites nothing at all — no exit code, no commit or digest, no path, no symbol, no claim-vocabulary term. " +
			"Every real record in this tree carries at least nine such citations; this one carries zero, so there is no evidence in it to read."
	}
	return ""
}
