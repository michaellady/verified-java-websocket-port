package autobahnsuite

import (
	"fmt"
	"path/filepath"
	"sort"
)

// Options narrows or binds a reconciliation.
type Options struct {
	// RequireAgent, when set, refuses a report filed under any other agent
	// name. This is the gate that stops a stale historical upstream report
	// from standing in for this run's evidence (AC4).
	RequireAgent string
	// FilteredCases lists manifest cases the run deliberately did not
	// address (a rerun of a subset). They are counted as FILTERED, which is
	// a run-scope fact, and never as skips or misses.
	FilteredCases []string
}

// Ledger is the exact per-dimension reconciliation AC3 requires.
//
// The class dimensions form an exact PARTITION of Executed:
//
//	Executed = Passed + NonStrict + Informational + Failed + Skipped + Unclassified
//
// and the scope dimensions form an exact partition of Expected:
//
//	Expected = Filtered + Executed + Missing
//
// TimedOut is deliberately NOT part of either partition: the suite records a
// timeout as a flag on a case that also carries a behavior class, so counting
// it as its own bucket would double-count. It is an OVERLAY, and it is split
// by kind — see the per-kind fields, because only the handshake kinds are
// faults.
type Ledger struct {
	Expected      int `json:"expected"`
	Selected      int `json:"selected"`
	Executed      int `json:"executed"`
	Passed        int `json:"passed"`
	Failed        int `json:"failed"`
	NonStrict     int `json:"non_strict"`
	Informational int `json:"informational"`
	Skipped       int `json:"skipped"`
	Filtered      int `json:"filtered"`
	TimedOut      int `json:"timed_out"`
	Missing       int `json:"missing"`
	Unclassified  int `json:"unclassified"`

	// Timeout overlays, split by KIND. An open- or close-handshake timeout
	// is a protocol-liveness fault. A connection-drop timeout is not: it
	// means the suite waited for the TESTEE to hang up first and gave up.
	// Both peers here follow the Java-faithful rule that the terminal
	// outcome arrives with transport EOF, so a server-role testee waits for
	// the suite's EOF while the suite waits for the testee's drop; the suite
	// resolves that by timing out and marking behaviorClose UNCLEAN, while
	// `behavior` — the conformance class — stays unaffected.
	OpenHandshakeTimeouts  int `json:"open_handshake_timeouts"`
	CloseHandshakeTimeouts int `json:"close_handshake_timeouts"`
	ConnectionDropTimeouts int `json:"connection_drop_timeouts"`

	// IndexEntryCount is the number of case records the report's OWN index
	// contains, counted independently of the manifest walk above. The
	// partition identities are computed by that walk and are therefore
	// self-consistent by construction; this is an OUTSIDE observation, so the
	// identity that binds it (see Identities) is the one a miscounted or
	// truncated report can actually violate.
	IndexEntryCount int `json:"index_entry_count"`
	// CaseReportCount is the number of per-case report files scanned, again
	// observed rather than derived. Zero when no cases directory was given.
	CaseReportCount int `json:"case_report_count"`

	// StrictRequiredNotOK counts manifest cases carrying
	// StrictPassRequired whose observed behavior is not OK. This is where
	// the manifest's per-case strictness declaration is CONSUMED: without
	// it, StrictPassRequired would record an expectation nothing checks.
	StrictRequiredNotOK      int      `json:"strict_required_not_ok"`
	StrictRequiredNotOKCases []string `json:"strict_required_not_ok_cases"`

	// Disagreements counts cross-source contradictions between the index and
	// the per-case reports it names: a differing behavior class, a differing
	// agent, a missing per-case report, or an index entry whose `reportfile`
	// names a file the scanned directory does not contain. A report that
	// contradicts itself cannot reconcile, and this is what binds the index
	// to the case files rather than letting the two be paired arbitrarily.
	Disagreements      int      `json:"disagreements"`
	DisagreementDetail []string `json:"disagreement_detail"`

	Agent             string   `json:"agent"`
	FailedCases       []string `json:"failed_cases"`
	NonStrictCases    []string `json:"non_strict_cases"`
	InformationalCase []string `json:"informational_cases"`
	SkippedCases      []string `json:"skipped_cases"`
	TimedOutCases     []string `json:"timed_out_cases"`
	MissingCases      []string `json:"missing_cases"`
	UnexpectedCases   []string `json:"unexpected_cases"`
	UnclassifiedCases []string `json:"unclassified_cases"`

	// StrictPassAll is the LITERAL reading of AC3: every in-scope case
	// behaved OK. NON-STRICT and INFORMATIONAL are not strict passes, so
	// this is false whenever either exists. It is never softened.
	StrictPassAll bool `json:"strict_pass_all"`
	// Reconciles is true only when the report ACCOUNTS FOR the manifest:
	// both partition identities hold, no reported case is absent from the
	// manifest, the report's own index size matches what was counted, every
	// expected case is either executed or explicitly filtered (nothing
	// missing), and the index does not contradict its per-case reports.
	//
	// The two partition identities alone are self-consistent by
	// construction — the counting loop assigns every manifest case to
	// exactly one scope bucket and every executed case to exactly one class
	// bucket, so they hold even for an EMPTY report, where all 247 cases
	// land in Missing. The missing/coverage and cross-source conditions are
	// what make this a check a report can fail.
	Reconciles bool `json:"reconciles"`
	// Identities records each checked equation and its evaluated values, so
	// a reader can see the arithmetic rather than trust the boolean.
	Identities []string `json:"identities"`
}

// Reconcile counts a wstest report against the manifest, dimension by
// dimension. `casesDir` may be empty, in which case timeout overlays cannot
// be read and TimedOut is reported as unavailable (-1) rather than guessed.
func Reconcile(manifest *Manifest, indexPath, casesDir string, options *Options) (*Ledger, error) {
	if manifest == nil {
		return nil, fmt.Errorf("no manifest")
	}
	if options == nil {
		options = &Options{}
	}
	agent, entries, err := readIndex(indexPath)
	if err != nil {
		return nil, err
	}
	if options.RequireAgent != "" && agent != options.RequireAgent {
		return nil, fmt.Errorf(
			"report is filed under agent %q but this gate requires %q: a report from another "+
				"run cannot satisfy it", agent, options.RequireAgent)
	}
	filtered := map[string]bool{}
	for _, caseID := range options.FilteredCases {
		filtered[caseID] = true
	}
	inManifest := make(map[string]bool, len(manifest.Cases))
	for _, entry := range manifest.Cases {
		inManifest[entry.CaseID] = true
	}

	var reports map[string]caseReport
	if casesDir != "" {
		reports, err = readCaseReports(casesDir)
		if err != nil {
			return nil, err
		}
	}

	ledger := &Ledger{
		Expected:        len(manifest.Cases),
		Agent:           agent,
		IndexEntryCount: len(entries),
		CaseReportCount: len(reports),
	}
	if casesDir == "" {
		ledger.TimedOut = -1
	}
	// Bind the index to the case files it names. Without this the index's
	// `reportfile` values are decorative and a stale case directory can be
	// paired with a freshly relabelled index.
	if casesDir != "" {
		presentFiles := map[string]bool{}
		names, globErr := filepath.Glob(filepath.Join(casesDir, "*.json"))
		if globErr != nil {
			return nil, fmt.Errorf("scan %s: %w", casesDir, globErr)
		}
		for _, name := range names {
			presentFiles[filepath.Base(name)] = true
		}
		for caseID, entry := range entries {
			if entry.ReportFile == "" {
				ledger.noteDisagreement(fmt.Sprintf(
					"case %s: index entry names no reportfile", caseID))
				continue
			}
			if !presentFiles[entry.ReportFile] {
				ledger.noteDisagreement(fmt.Sprintf(
					"case %s: index names reportfile %q which is not in the scanned cases directory",
					caseID, entry.ReportFile))
			}
		}
	}
	for _, entry := range manifest.Cases {
		if filtered[entry.CaseID] {
			ledger.Filtered++
			continue
		}
		result, ran := entries[entry.CaseID]
		if !ran {
			ledger.Missing++
			ledger.MissingCases = append(ledger.MissingCases, entry.CaseID)
			continue
		}
		ledger.Executed++
		switch result.Behavior {
		case BehaviorOK:
			ledger.Passed++
		case BehaviorNonStrict:
			ledger.NonStrict++
			ledger.NonStrictCases = append(ledger.NonStrictCases, entry.CaseID)
		case BehaviorInformational:
			ledger.Informational++
			ledger.InformationalCase = append(ledger.InformationalCase, entry.CaseID)
		case BehaviorFailed:
			ledger.Failed++
			ledger.FailedCases = append(ledger.FailedCases, entry.CaseID)
		case BehaviorUnimplemented:
			ledger.Skipped++
			ledger.SkippedCases = append(ledger.SkippedCases, entry.CaseID)
		default:
			ledger.Unclassified++
			ledger.UnclassifiedCases = append(ledger.UnclassifiedCases,
				fmt.Sprintf("%s=%s", entry.CaseID, result.Behavior))
		}
		if entry.StrictPassRequired && result.Behavior != BehaviorOK {
			ledger.StrictRequiredNotOK++
			ledger.StrictRequiredNotOKCases = append(ledger.StrictRequiredNotOKCases,
				fmt.Sprintf("%s=%s", entry.CaseID, result.Behavior))
		}
		if report, ok := reports[entry.CaseID]; ok {
			// The index and the per-case report are two renderings of the
			// same case. If they disagree, one of them is from another run.
			if report.Behavior != result.Behavior {
				ledger.noteDisagreement(fmt.Sprintf(
					"case %s: index says behavior %q but its per-case report says %q",
					entry.CaseID, result.Behavior, report.Behavior))
			}
			if report.Agent != agent {
				ledger.noteDisagreement(fmt.Sprintf(
					"case %s: per-case report is filed under agent %q but the index is %q",
					entry.CaseID, report.Agent, agent))
			}
			if report.WasOpenHandshakeTimeout {
				ledger.OpenHandshakeTimeouts++
			}
			if report.WasCloseHandshakeTimeout {
				ledger.CloseHandshakeTimeouts++
			}
			if report.WasServerConnectionDropTimeout {
				ledger.ConnectionDropTimeouts++
			}
			if report.WasOpenHandshakeTimeout || report.WasCloseHandshakeTimeout ||
				report.WasServerConnectionDropTimeout {
				ledger.TimedOut++
				ledger.TimedOutCases = append(ledger.TimedOutCases, entry.CaseID)
			}
		} else if casesDir != "" {
			ledger.noteDisagreement(fmt.Sprintf(
				"case %s: the index scores it but no per-case report exists for it",
				entry.CaseID))
		}
	}
	for caseID := range entries {
		if !inManifest[caseID] {
			ledger.UnexpectedCases = append(ledger.UnexpectedCases, caseID)
		}
	}
	sort.Strings(ledger.UnexpectedCases)
	sort.Strings(ledger.MissingCases)
	sort.Strings(ledger.NonStrictCases)
	sort.Strings(ledger.InformationalCase)
	sort.Strings(ledger.FailedCases)
	sort.Strings(ledger.SkippedCases)
	sort.Strings(ledger.TimedOutCases)

	ledger.Selected = ledger.Expected - ledger.Filtered
	classSum := ledger.Passed + ledger.NonStrict + ledger.Informational +
		ledger.Failed + ledger.Skipped + ledger.Unclassified
	scopeSum := ledger.Filtered + ledger.Executed + ledger.Missing
	ledger.Identities = []string{
		fmt.Sprintf("expected(%d) = filtered(%d) + executed(%d) + missing(%d) -> %d",
			ledger.Expected, ledger.Filtered, ledger.Executed, ledger.Missing, scopeSum),
		fmt.Sprintf("selected(%d) = expected(%d) - filtered(%d)",
			ledger.Selected, ledger.Expected, ledger.Filtered),
		fmt.Sprintf(
			"executed(%d) = passed(%d) + non_strict(%d) + informational(%d) + failed(%d) + "+
				"skipped(%d) + unclassified(%d) -> %d",
			ledger.Executed, ledger.Passed, ledger.NonStrict, ledger.Informational,
			ledger.Failed, ledger.Skipped, ledger.Unclassified, classSum),
		fmt.Sprintf("unexpected_cases(%d) must be 0", len(ledger.UnexpectedCases)),
		// The three identities below are the NON-self-consistent ones: each
		// compares the counting walk against something observed outside it.
		fmt.Sprintf(
			"coverage: missing(%d) must be 0 - every expected case is executed or explicitly filtered",
			ledger.Missing),
		fmt.Sprintf(
			"index_entry_count(%d) = executed(%d) + unexpected(%d) -> %d",
			ledger.IndexEntryCount, ledger.Executed, len(ledger.UnexpectedCases),
			ledger.Executed+len(ledger.UnexpectedCases)),
		fmt.Sprintf(
			"cross-source disagreements(%d) between the index and its per-case reports must be 0",
			ledger.Disagreements),
		fmt.Sprintf(
			"timed_out(%d) is an OVERLAY, not a partition member = open(%d) + close(%d) + "+
				"drop(%d) counted per case",
			ledger.TimedOut, ledger.OpenHandshakeTimeouts, ledger.CloseHandshakeTimeouts,
			ledger.ConnectionDropTimeouts),
	}
	ledger.Reconciles = scopeSum == ledger.Expected &&
		classSum == ledger.Executed &&
		len(ledger.UnexpectedCases) == 0 &&
		// Coverage: a report that simply omits cases has not reconciled with
		// the manifest, it has failed to address it. This is the condition
		// that stops an EMPTY report from reconciling.
		ledger.Missing == 0 &&
		// The report's own index size must agree with what was counted from
		// it, which a truncated or double-counted index cannot satisfy.
		ledger.IndexEntryCount == ledger.Executed+len(ledger.UnexpectedCases) &&
		// And the index must not contradict the per-case reports it names.
		ledger.Disagreements == 0
	ledger.StrictPassAll = ledger.Reconciles &&
		ledger.Executed == ledger.Selected &&
		ledger.Passed == ledger.Executed &&
		ledger.StrictRequiredNotOK == 0
	return ledger, nil
}

// noteDisagreement records one cross-source contradiction. The detail list is
// capped so a wholly mismatched pair of directories cannot produce a
// multi-megabyte ledger, but the COUNT is always exact.
func (ledger *Ledger) noteDisagreement(detail string) {
	ledger.Disagreements++
	const maxDetail = 20
	if len(ledger.DisagreementDetail) < maxDetail {
		ledger.DisagreementDetail = append(ledger.DisagreementDetail, detail)
	}
}

// Verdict is the outcome of checking a ledger against what a SUBJECT was
// supposed to demonstrate.
type Verdict struct {
	Subject    Subject `json:"subject"`
	AsExpected bool    `json:"as_expected"`
	Reason     string  `json:"reason"`
}

// Discriminate checks a ledger against the expectation its subject carries.
//
// This is the AC4 mechanism: the SAME manifest and the SAME reconciliation
// must tell the real port, the Java baseline, an empty/stub negative control
// and a planted mutant apart. A control that does not misbehave has not
// proven the gate can catch anything, so it fails its own expectation.
func Discriminate(subject Subject, ledger *Ledger) Verdict {
	if ledger == nil {
		return Verdict{Subject: subject, Reason: "no ledger"}
	}
	if !ledger.Reconciles {
		return Verdict{
			Subject: subject,
			Reason:  "ledger does not reconcile; no verdict is possible from it",
		}
	}
	// broken counts only cases the suite ACTUALLY SCORED and scored badly.
	// Missing is deliberately excluded: a case the run never produced is an
	// absence of evidence, not evidence of a deviation. Counting it as
	// discrimination is what let an empty index and a crashed process pass
	// as successful controls. Reconciles already requires Missing == 0, so a
	// truncated run cannot reach this function at all; excluding Missing here
	// keeps that true independently of the reconciliation predicate.
	broken := ledger.Failed + ledger.Skipped + ledger.Unclassified
	if ledger.Executed == 0 {
		return Verdict{
			Subject: subject,
			Reason: "the run scored no cases at all; an empty report cannot demonstrate " +
				"anything about any subject",
		}
	}
	switch subject {
	case SubjectUnderTest, SubjectJavaBaseline:
		// AC3 is literal: "every in-scope case is strict-pass". The manifest
		// carries StrictPassRequired on every case, so the verdict CONSUMES
		// that declaration. NON-STRICT and INFORMATIONAL are not strict
		// passes, and a subject that produced any of them has not met AC3.
		return Verdict{
			Subject:    subject,
			AsExpected: ledger.StrictPassAll,
			Reason: fmt.Sprintf(
				"AC3 requires every in-scope case to be a STRICT pass; observed "+
					"strict_pass_all=%t with %d strict-required cases not OK "+
					"(failed=%d non_strict=%d informational=%d skipped=%d unclassified=%d missing=%d)",
				ledger.StrictPassAll, ledger.StrictRequiredNotOK, ledger.Failed,
				ledger.NonStrict, ledger.Informational, ledger.Skipped,
				ledger.Unclassified, ledger.Missing),
		}
	case SubjectNegativeControl:
		// An empty/stub endpoint implements nothing, so every case the suite
		// actually SCORES must come back broken, and nothing may pass.
		//
		// INFORMATIONAL is excluded from the scoreable set, and that is a
		// MEASURED fact rather than an allowance: cases 7.1.6, 7.13.1 and
		// 7.13.2 come back INFORMATIONAL from the real port and from the
		// wholly inert control alike, so the suite assigns that class by
		// construction and never as a pass or a failure. Requiring them to
		// "fail" would demand something the suite cannot express.
		//
		// The load-bearing conditions are the first two: a negative control
		// that passed even one scored case would prove the wiring, not the
		// port, and would invalidate the gate.
		scoreable := ledger.Selected - ledger.Informational
		return Verdict{
			Subject: subject,
			AsExpected: ledger.Passed == 0 && ledger.NonStrict == 0 &&
				scoreable > 0 && broken == scoreable &&
				// The control must have been SCORED end to end. Without this,
				// a control that died early "discriminates" by absence.
				ledger.Executed == ledger.Selected && ledger.Missing == 0,
			Reason: fmt.Sprintf(
				"expected 0 passed, 0 non-strict, and all %d scoreable cases OBSERVED broken "+
					"(%d selected minus %d informational-by-construction), across a complete "+
					"run; observed passed=%d non_strict=%d broken=%d executed=%d missing=%d",
				scoreable, ledger.Selected, ledger.Informational,
				ledger.Passed, ledger.NonStrict, broken, ledger.Executed, ledger.Missing),
		}
	case SubjectMutant:
		// A mutant must be caught by an OBSERVED bad score on a case the
		// suite actually ran to completion. A mutant run that terminated
		// early leaves its remaining cases Missing, and Missing is not a
		// deviation the suite detected — it is a run that did not happen.
		return Verdict{
			Subject: subject,
			AsExpected: broken > 0 &&
				ledger.Executed == ledger.Selected && ledger.Missing == 0,
			Reason: fmt.Sprintf(
				"expected the planted deviation to break at least one case across a COMPLETE "+
					"run; observed %d broken (failed=%d skipped=%d unclassified=%d) with "+
					"executed=%d of selected=%d and missing=%d",
				broken, ledger.Failed, ledger.Skipped, ledger.Unclassified,
				ledger.Executed, ledger.Selected, ledger.Missing),
		}
	default:
		return Verdict{Subject: subject, Reason: "unknown subject"}
	}
}
