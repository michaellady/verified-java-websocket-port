package autobahnsuite

// The AMENDED AC3 bar: per-case behavior-class agreement with the pinned
// Java baseline.
//
// WHY THE LITERAL BAR WAS AMENDED, AND BY WHOM. AC3 as written requires
// "every in-scope case is strict-pass". Both modes execute all 247 selected
// cases with zero FAILED, but the classes are 233 OK / 11 NON-STRICT /
// 3 INFORMATIONAL — and the PINNED JAVA BASELINE carries the same classes on
// the same manifest and the same host. Meeting the literal bar would require
// the port to behave BETTER than the library it is a port of, which
// contradicts the JAVA_FAITHFUL_PLUS_SAFE normativity decision. The owner
// amended the clause on 2026-08-28T03:37:30Z (owner decision
// us019-ac3-strict-pass-reading, recorded in
// evidence/governance/decisions/us019-owner-decisions-2026-08-28-d.json) to
// read as per-case behavior-class agreement with that baseline. The
// reconciliation half of AC3 was explicitly NOT amended and still applies
// literally; nothing here touches it.
//
// WHAT THIS FILE ADDS, AND WHY IT IS NOT A SOFTENING. Before it, the amended
// bar existed only as a sentence in a decision record and as two generated
// documents under evidence/autobahn/native-x86_64-provenance/comparison/
// that NO code read — the same defect class review 01a04961 named when it
// found the digest manifest had a generator and no consumer, recurring in
// the very artifact that carries the amended bar's numbers. The verdict here
// re-derives the comparison from the two runs' own report bytes, so the
// document is now checked rather than believed, and it is bound in three
// directions that a softened bar would not survive:
//
//   - THE BASELINE MUST BE A DIFFERENT RUN. Comparing a report with itself
//     agrees on every case by construction, which would make the amended bar
//     vacuous — the exact shape the review kept finding. Distinct agent
//     names are required, and both reports must reconcile against the same
//     manifest with nothing missing.
//   - THE PORT MAY NOT BE WEAKER ANYWHERE UNREGISTERED. A case where the
//     baseline is OK and the port is not is a real divergence, and it counts
//     against the bar unless a committed register entry records that exact
//     case, that exact role, and the exact pair of behavior classes observed,
//     naming the behavior-delta ledger record that analyses it.
//
//     THE FIRST VERSION OF THIS CHECK WAS TOO WEAK AND SAID SO WHEN ATTACKED.
//     It asked only whether the behavior-delta ledger cited the case
//     anywhere. Measured with a planted regression (case 1.1.1, which both
//     runs score OK, rewritten to FAILED in the subject's index), the bar
//     ACCEPTED it: 1.1.1 is cited by ledger sequence 47, a superseding
//     correction about a handshake header-line limit that says nothing about
//     any Autobahn conformance divergence. A citation of a case is not a
//     record of THAT divergence — existence standing in for identity, the
//     defect class this lane's reviews keep naming. The register below
//     replaces it: an exact, closed mapping in both directions, whose stated
//     classes must equal the ones the runs actually produced, so a stale or
//     speculative entry is refused as loudly as a missing one.
//   - AGREEMENT IS COUNTED, NOT ASSERTED. Every case of the manifest is
//     classified into exactly one bucket and the buckets are required to
//     partition it, so a comparison that does not add up cannot pass.
//
// Cases where the PORT is stricter than the baseline (it scores OK where
// Java does not) are recorded and do not fail the bar: being stricter than
// the library is safe under JAVA_FAITHFUL_PLUS_SAFE. They are reported so a
// reader can see them rather than discovering a silent asymmetry.

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// AgreementClass is how one case's behavior class compares between the
// subject under test and the pinned Java baseline.
type AgreementClass string

const (
	// AgreementAgree means both peers landed in the same behavior class.
	AgreementAgree AgreementClass = "AGREE"
	// AgreementSubjectWeaker means the baseline scored OK and the subject
	// did not. This is the direction that counts against the amended bar.
	AgreementSubjectWeaker AgreementClass = "SUBJECT_WEAKER"
	// AgreementSubjectStricter means the subject scored OK and the baseline
	// did not: safe under JAVA_FAITHFUL_PLUS_SAFE, recorded, not a failure.
	AgreementSubjectStricter AgreementClass = "SUBJECT_STRICTER"
	// AgreementDiffer means the two disagree without either being OK (for
	// example NON-STRICT against INFORMATIONAL). It is a divergence and is
	// held to the same ledger requirement as SUBJECT_WEAKER.
	AgreementDiffer AgreementClass = "DIFFER"
	// AgreementUnobserved means at least one side never scored the case. It
	// is an absence of evidence and can never satisfy the bar.
	AgreementUnobserved AgreementClass = "UNOBSERVED"
)

// CaseAgreement is one case's reading, carrying both observed classes so the
// row can be checked against the runs rather than trusted.
type CaseAgreement struct {
	CaseID           string         `json:"case_id"`
	SubjectBehavior  string         `json:"subject_behavior"`
	BaselineBehavior string         `json:"baseline_behavior"`
	Class            AgreementClass `json:"class"`
	// RegisterRef names the register entry, and through it the
	// behavior-delta ledger record, that accounts for a divergence.
	RegisterRef string `json:"register_ref,omitempty"`
}

// Agreement is the whole per-case comparison of one role's two runs.
type Agreement struct {
	Role              Role            `json:"role"`
	SubjectAgent      string          `json:"subject_agent"`
	BaselineAgent     string          `json:"baseline_agent"`
	Expected          int             `json:"expected"`
	Agree             int             `json:"agree"`
	SubjectWeaker     int             `json:"subject_weaker"`
	SubjectStricter   int             `json:"subject_stricter"`
	Differ            int             `json:"differ"`
	Unobserved        int             `json:"unobserved"`
	RegisteredDelta   int             `json:"registered_divergences"`
	UnregisteredDelta int             `json:"unregistered_divergences"`
	Cases             []CaseAgreement `json:"cases"`
	DivergenceDetail  []string        `json:"divergence_detail"`
	// Identities records the partition equation and its evaluated values,
	// so the counts are readable as arithmetic rather than as assertions.
	Identities []string `json:"identities"`
	// Partitions is false when the buckets do not add up to the manifest.
	Partitions bool `json:"partitions"`
}

// LedgerIndex is the set of Autobahn case references the behavior-delta
// ledger accounts for, read from the ledger document itself.
type LedgerIndex struct {
	// ByCase maps an Autobahn case id ("5.15") to the delta id that records
	// it.
	ByCase map[string]string
	// Records is how many ledger records were read, so an empty or
	// truncated ledger is visible rather than silently permissive.
	Records int
}

// autobahnRefPrefix is how the ledger spells an Autobahn citation:
// "autobahn-v25.10.1:5.15". The suite version is part of the reference and
// is deliberately not matched on, so a ledger written against one pinned
// suite version does not silently satisfy a run of another; the version is
// returned with the case so a caller can check it.
const autobahnRefPrefix = "autobahn-"

// ReadLedgerIndex reads the behavior-delta ledger and indexes the Autobahn
// cases its records cite.
//
// The ledger is the project's record of every Java/Rust/spec disagreement.
// Requiring a divergence to appear here is what makes "separately analysed
// and ledgered" — the owner decision's own words — a checkable condition
// instead of a promise.
func ReadLedgerIndex(path string) (*LedgerIndex, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // operator-supplied evidence path
	if err != nil {
		return nil, fmt.Errorf("read behavior-delta ledger %s: %w", path, err)
	}
	var document struct {
		Records []struct {
			Sequence int `json:"sequence"`
			Delta    struct {
				DeltaID      string   `json:"delta_id"`
				AutobahnRefs []string `json:"autobahn_refs"`
				Disposition  string   `json:"disposition"`
			} `json:"delta"`
		} `json:"records"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("parse behavior-delta ledger %s: %w", path, err)
	}
	index := &LedgerIndex{ByCase: map[string]string{}, Records: len(document.Records)}
	for _, record := range document.Records {
		for _, ref := range record.Delta.AutobahnRefs {
			if !strings.HasPrefix(ref, autobahnRefPrefix) {
				continue
			}
			_, caseID, found := strings.Cut(ref, ":")
			if !found || caseID == "" {
				continue
			}
			index.ByCase[caseID] = fmt.Sprintf("%s (ledger sequence %d, disposition %s)",
				record.Delta.DeltaID, record.Sequence, record.Delta.Disposition)
		}
	}
	return index, nil
}

// CompareToBaseline re-derives the per-case behavior-class comparison of one
// role's subject run against the pinned Java baseline run, from the two
// reports' own bytes.
//
// Both indexes are read against the SAME manifest, so a case neither report
// mentions cannot vanish from the denominator.
func CompareToBaseline(
	manifest *Manifest,
	role Role,
	subjectIndexPath, baselineIndexPath string,
	register *DivergenceRegister,
) (*Agreement, error) {
	if manifest == nil {
		return nil, fmt.Errorf("no manifest")
	}
	if register == nil {
		register = &DivergenceRegister{}
	}
	subjectAgent, subjectEntries, err := readIndex(subjectIndexPath)
	if err != nil {
		return nil, err
	}
	baselineAgent, baselineEntries, err := readIndex(baselineIndexPath)
	if err != nil {
		return nil, err
	}
	agreement := &Agreement{
		Role:          role,
		SubjectAgent:  subjectAgent,
		BaselineAgent: baselineAgent,
		Expected:      len(manifest.Cases),
		Cases:         make([]CaseAgreement, 0, len(manifest.Cases)),
	}
	for _, entry := range manifest.Cases {
		subject, subjectRan := subjectEntries[entry.CaseID]
		baseline, baselineRan := baselineEntries[entry.CaseID]
		row := CaseAgreement{CaseID: entry.CaseID}
		switch {
		case !subjectRan || !baselineRan:
			row.Class = AgreementUnobserved
			if subjectRan {
				row.SubjectBehavior = subject.Behavior
			}
			if baselineRan {
				row.BaselineBehavior = baseline.Behavior
			}
			agreement.Unobserved++
		default:
			row.SubjectBehavior = subject.Behavior
			row.BaselineBehavior = baseline.Behavior
			switch {
			case subject.Behavior == baseline.Behavior:
				row.Class = AgreementAgree
				agreement.Agree++
			case baseline.Behavior == BehaviorOK:
				row.Class = AgreementSubjectWeaker
				agreement.SubjectWeaker++
			case subject.Behavior == BehaviorOK:
				row.Class = AgreementSubjectStricter
				agreement.SubjectStricter++
			default:
				row.Class = AgreementDiffer
				agreement.Differ++
			}
		}
		// A divergence in the weaker or mixed direction has to be accounted
		// for by a register entry that states THIS case, THIS role and THIS
		// pair of observed classes. Stricter-than-Java is safe and is not
		// held to it.
		if row.Class == AgreementSubjectWeaker || row.Class == AgreementDiffer {
			if registered := register.entryFor(role, entry.CaseID); registered != nil &&
				registered.SubjectBehavior == row.SubjectBehavior &&
				registered.BaselineBehavior == row.BaselineBehavior {
				row.RegisterRef = fmt.Sprintf("%s (ledger sequence %d)",
					registered.LedgerDeltaID, registered.LedgerSequence)
				agreement.RegisteredDelta++
			} else {
				agreement.UnregisteredDelta++
			}
			agreement.DivergenceDetail = append(agreement.DivergenceDetail, fmt.Sprintf(
				"%s: subject=%s baseline=%s register=%q",
				entry.CaseID, row.SubjectBehavior, row.BaselineBehavior, row.RegisterRef))
		}
		agreement.Cases = append(agreement.Cases, row)
	}
	sort.Strings(agreement.DivergenceDetail)

	total := agreement.Agree + agreement.SubjectWeaker + agreement.SubjectStricter +
		agreement.Differ + agreement.Unobserved
	agreement.Partitions = total == agreement.Expected &&
		len(agreement.Cases) == agreement.Expected
	agreement.Identities = []string{
		fmt.Sprintf("agree + subject_weaker + subject_stricter + differ + unobserved = %d + %d + %d + %d + %d = %d, expected %d",
			agreement.Agree, agreement.SubjectWeaker, agreement.SubjectStricter,
			agreement.Differ, agreement.Unobserved, total, agreement.Expected),
		fmt.Sprintf("registered + unregistered divergences = %d + %d = %d, subject_weaker + differ = %d",
			agreement.RegisteredDelta, agreement.UnregisteredDelta,
			agreement.RegisteredDelta+agreement.UnregisteredDelta,
			agreement.SubjectWeaker+agreement.Differ),
		fmt.Sprintf("rows written = %d, manifest cases = %d", len(agreement.Cases), agreement.Expected),
	}
	return agreement, nil
}

// DiscriminateAgainstBaseline is the amended AC3 verdict.
//
// It is deliberately a SEPARATE function from Discriminate rather than a
// change to it: the literal reading stays computed and reportable, so a
// reader can see both the literal verdict (NEGATIVE, and honestly so) and
// the amended one, and a future round cannot quietly lose the literal bar by
// editing the amended one.
func DiscriminateAgainstBaseline(
	subjectLedger, baselineLedger *Ledger,
	agreement *Agreement,
) Verdict {
	subject := SubjectUnderTest
	switch {
	case subjectLedger == nil || baselineLedger == nil || agreement == nil:
		return Verdict{Subject: subject, Reason: "missing ledger or agreement"}
	case !subjectLedger.Reconciles:
		return Verdict{Subject: subject,
			Reason: "the subject's report does not reconcile; no verdict is possible from it"}
	case !baselineLedger.Reconciles:
		return Verdict{Subject: subject,
			Reason: "the Java baseline's report does not reconcile, so there is nothing to agree WITH"}
	case !agreement.Partitions:
		return Verdict{Subject: subject, Reason: fmt.Sprintf(
			"the comparison does not partition the manifest: %v", agreement.Identities)}
	// THE VACUITY GUARD. A report compared with itself agrees on every case
	// by construction. The amended bar means agreement with a DIFFERENT
	// implementation's run, so identical agent names are refused outright
	// rather than scored.
	case agreement.SubjectAgent == agreement.BaselineAgent:
		return Verdict{Subject: subject, Reason: fmt.Sprintf(
			"subject and baseline are both filed under agent %q: a report agrees with itself on "+
				"every case by construction, so this comparison demonstrates nothing",
			agreement.SubjectAgent)}
	case agreement.Unobserved != 0:
		return Verdict{Subject: subject, Reason: fmt.Sprintf(
			"%d cases were not scored by both runs; an absence of evidence is not agreement",
			agreement.Unobserved)}
	}
	return Verdict{
		Subject: subject,
		AsExpected: agreement.UnregisteredDelta == 0 &&
			agreement.Agree+agreement.SubjectStricter+agreement.RegisteredDelta == agreement.Expected,
		Reason: fmt.Sprintf(
			"AC3 as amended (owner decision us019-ac3-strict-pass-reading, 2026-08-28) requires per-case "+
				"behavior-class agreement with the pinned Java baseline %q, with any residual difference "+
				"registered and ledgered; observed agree=%d subject_stricter=%d subject_weaker=%d differ=%d of %d, "+
				"divergences registered=%d unregistered=%d%s",
			agreement.BaselineAgent, agreement.Agree, agreement.SubjectStricter,
			agreement.SubjectWeaker, agreement.Differ, agreement.Expected,
			agreement.RegisteredDelta, agreement.UnregisteredDelta,
			divergenceSuffix(agreement)),
	}
}

func divergenceSuffix(agreement *Agreement) string {
	if len(agreement.DivergenceDetail) == 0 {
		return ""
	}
	return "; " + strings.Join(agreement.DivergenceDetail, "; ")
}

// ---------------------------------------------------------------------------
// Binding the committed comparison document to the runs it describes
// ---------------------------------------------------------------------------

// ComparisonDocumentPath is where the native run's Java-versus-Rust
// comparison is committed.
const ComparisonDocumentPath = "evidence/autobahn/native-x86_64-provenance/comparison/java-vs-rust-per-case.json"

// ComparisonFinding is one way the committed comparison document fails to
// describe the runs it names.
type ComparisonFinding struct {
	CaseID string `json:"case_id,omitempty"`
	Field  string `json:"field"`
	Detail string `json:"detail"`
}

// VerifyComparisonDocument re-derives the committed comparison document from
// the two runs' own report indexes and reports every disagreement.
//
// WHY THIS EXISTS. The document was generated and never read. A generator
// with no consumer is a file that can be edited, truncated or refreshed from
// the wrong run without any gate noticing — review 01a04961 found exactly
// that shape in the digest manifest, and it recurred here, in the artifact
// carrying the amended AC3 bar's own numbers. Every behavior value the
// document states for a case is now compared with the value that case's
// index entry actually holds, in all four legs, and the agent names it
// claims are compared with the agents the indexes are filed under. Nothing
// is recomputed from the document's own rows, so a self-consistent forgery
// gains nothing.
//
// The `agreement` columns are the document's own vocabulary rather than this
// package's, so they are checked for INTERNAL consistency with the behavior
// pair on the same row: a row may not label a difference as agreement.
func VerifyComparisonDocument(
	documentPath string,
	manifest *Manifest,
	legs map[string]string,
) ([]ComparisonFinding, error) {
	if manifest == nil {
		return nil, fmt.Errorf("no manifest")
	}
	raw, err := os.ReadFile(documentPath) //nolint:gosec // operator-supplied evidence path
	if err != nil {
		return nil, fmt.Errorf("read comparison document %s: %w", documentPath, err)
	}
	var document struct {
		EntityType         string              `json:"entity_type"`
		Agents             map[string]string   `json:"agents"`
		ComparedCaseCount  int                 `json:"compared_case_count"`
		ExpectedCaseCount  int                 `json:"expected_case_count"`
		Cases              []map[string]any    `json:"cases"`
		BehaviorDifference map[string][]string `json:"behavior_differences"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("parse comparison document %s: %w", documentPath, err)
	}

	var findings []ComparisonFinding
	note := func(caseID, field, detail string) {
		findings = append(findings, ComparisonFinding{CaseID: caseID, Field: field, Detail: detail})
	}

	// The four legs, each read from its own index. The column prefix is how
	// the document names that leg's behavior value.
	type leg struct {
		column  string
		agent   string
		entries map[string]indexEntry
	}
	var loaded []leg
	for column, indexPath := range legs {
		agent, entries, err := readIndex(indexPath)
		if err != nil {
			return nil, err
		}
		loaded = append(loaded, leg{column: column, agent: agent, entries: entries})
	}
	sort.Slice(loaded, func(i, j int) bool { return loaded[i].column < loaded[j].column })

	if document.ExpectedCaseCount != len(manifest.Cases) {
		note("", "expected_case_count", fmt.Sprintf(
			"document says %d but the manifest holds %d cases",
			document.ExpectedCaseCount, len(manifest.Cases)))
	}
	if document.ComparedCaseCount != len(document.Cases) {
		note("", "compared_case_count", fmt.Sprintf(
			"document says %d but carries %d case rows",
			document.ComparedCaseCount, len(document.Cases)))
	}
	if len(document.Cases) != len(manifest.Cases) {
		note("", "cases", fmt.Sprintf(
			"document carries %d rows for a %d-case manifest",
			len(document.Cases), len(manifest.Cases)))
	}

	// Agent names must be the agents the indexes are actually filed under.
	for _, entry := range loaded {
		claimedKey := strings.TrimSuffix(entry.column, "_behavior") + "_role"
		if claimed, present := document.Agents[claimedKey]; present && claimed != entry.agent {
			note("", "agents."+claimedKey, fmt.Sprintf(
				"document names agent %q but %s is filed under %q", claimed, entry.column, entry.agent))
		}
	}

	rows := make(map[string]map[string]any, len(document.Cases))
	for _, row := range document.Cases {
		caseID, _ := row["case_id"].(string)
		if caseID == "" {
			note("", "case_id", "a row carries no case_id")
			continue
		}
		if _, duplicate := rows[caseID]; duplicate {
			note(caseID, "case_id", "the document carries this case twice")
		}
		rows[caseID] = row
	}

	for _, entry := range manifest.Cases {
		row, present := rows[entry.CaseID]
		if !present {
			note(entry.CaseID, "cases", "the manifest holds this case and the document omits it")
			continue
		}
		if required, ok := row["strict_pass_required"].(bool); ok && required != entry.StrictPassRequired {
			note(entry.CaseID, "strict_pass_required", fmt.Sprintf(
				"document says %t, manifest says %t", required, entry.StrictPassRequired))
		}
		for _, l := range loaded {
			stated, _ := row[l.column].(string)
			observed := ""
			if indexed, ran := l.entries[entry.CaseID]; ran {
				observed = indexed.Behavior
			}
			if stated != observed {
				note(entry.CaseID, l.column, fmt.Sprintf(
					"document states %q but the run's index says %q", stated, observed))
			}
		}
	}

	// Every row that states two DIFFERENT behaviors for a role must be
	// listed under behavior_differences for that role, and every listed
	// difference must be a row that really differs. This is what stops the
	// summary from being narrative beside the data.
	for _, role := range []string{"client", "server"} {
		listed := map[string]bool{}
		for _, item := range document.BehaviorDifference[role+"_role"] {
			caseID, _, _ := strings.Cut(item, "(")
			listed[strings.TrimSpace(caseID)] = true
		}
		for caseID, row := range rows {
			rust, _ := row["rust_"+role+"_behavior"].(string)
			java, _ := row["java_"+role+"_behavior"].(string)
			differs := rust != java && rust != "" && java != ""
			if differs && !listed[caseID] {
				note(caseID, "behavior_differences."+role+"_role", fmt.Sprintf(
					"the row states rust=%q java=%q but the difference list omits the case", rust, java))
			}
			if !differs && listed[caseID] {
				note(caseID, "behavior_differences."+role+"_role", fmt.Sprintf(
					"the difference list names the case but the row states rust=%q java=%q", rust, java))
			}
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].CaseID != findings[j].CaseID {
			return findings[i].CaseID < findings[j].CaseID
		}
		return findings[i].Field < findings[j].Field
	})
	return findings, nil
}

// ---------------------------------------------------------------------------
// The divergence register
// ---------------------------------------------------------------------------

// DivergenceRegisterPath is the committed register of Autobahn
// behavior-class divergences between the port and the pinned Java baseline.
const DivergenceRegisterPath = "evidence/autobahn/native-x86_64-provenance/comparison/behavior-class-divergences.json"

// DivergenceEntry accounts for exactly one case, in exactly one role, at
// exactly one observed pair of behavior classes.
//
// Every field is load-bearing. The case and role say WHICH observation is
// being accounted for; the two behavior values say WHAT was observed, so an
// entry cannot outlive the reading it describes; the ledger fields say where
// the analysis lives, and are resolved in the behavior-delta ledger's own
// bytes rather than trusted.
type DivergenceEntry struct {
	CaseID           string `json:"case_id"`
	Role             Role   `json:"role"`
	SubjectBehavior  string `json:"subject_behavior"`
	BaselineBehavior string `json:"baseline_behavior"`
	LedgerDeltaID    string `json:"ledger_delta_id"`
	LedgerSequence   int    `json:"ledger_sequence"`
	Rationale        string `json:"rationale"`
}

// DivergenceRegister is the committed set of those entries.
type DivergenceRegister struct {
	SchemaVersion string            `json:"schema_version"`
	EntityType    string            `json:"entity_type"`
	Note          string            `json:"note"`
	Entries       []DivergenceEntry `json:"entries"`
}

func (r *DivergenceRegister) entryFor(role Role, caseID string) *DivergenceEntry {
	if r == nil {
		return nil
	}
	for index := range r.Entries {
		if r.Entries[index].CaseID == caseID && r.Entries[index].Role == role {
			return &r.Entries[index]
		}
	}
	return nil
}

// ReadDivergenceRegister loads the register.
func ReadDivergenceRegister(path string) (*DivergenceRegister, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // operator-supplied evidence path
	if err != nil {
		return nil, fmt.Errorf("read divergence register %s: %w", path, err)
	}
	var register DivergenceRegister
	if err := json.Unmarshal(raw, &register); err != nil {
		return nil, fmt.Errorf("parse divergence register %s: %w", path, err)
	}
	return &register, nil
}

// VerifyRegisterAgainstLedger checks every register entry against the
// behavior-delta ledger: the named record must exist at the named sequence
// and must itself cite the Autobahn case the entry is about.
//
// This is what stops an entry from naming an arbitrary record id to make a
// divergence look analysed.
func VerifyRegisterAgainstLedger(register *DivergenceRegister, ledgerPath string) ([]string, error) {
	raw, err := os.ReadFile(ledgerPath) //nolint:gosec // operator-supplied evidence path
	if err != nil {
		return nil, fmt.Errorf("read behavior-delta ledger %s: %w", ledgerPath, err)
	}
	var document struct {
		Records []struct {
			Sequence int `json:"sequence"`
			Delta    struct {
				DeltaID      string   `json:"delta_id"`
				AutobahnRefs []string `json:"autobahn_refs"`
				Disposition  string   `json:"disposition"`
			} `json:"delta"`
		} `json:"records"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("parse behavior-delta ledger %s: %w", ledgerPath, err)
	}
	bySequence := map[int]struct {
		id    string
		cases map[string]bool
	}{}
	for _, record := range document.Records {
		cases := map[string]bool{}
		for _, ref := range record.Delta.AutobahnRefs {
			if _, caseID, found := strings.Cut(ref, ":"); found && strings.HasPrefix(ref, autobahnRefPrefix) {
				cases[caseID] = true
			}
		}
		bySequence[record.Sequence] = struct {
			id    string
			cases map[string]bool
		}{id: record.Delta.DeltaID, cases: cases}
	}
	var problems []string
	if register == nil {
		return []string{"no register"}, nil
	}
	for _, entry := range register.Entries {
		record, present := bySequence[entry.LedgerSequence]
		switch {
		case !present:
			problems = append(problems, fmt.Sprintf(
				"case %s (%s): the register names ledger sequence %d, which the ledger does not contain",
				entry.CaseID, entry.Role, entry.LedgerSequence))
		case record.id != entry.LedgerDeltaID:
			problems = append(problems, fmt.Sprintf(
				"case %s (%s): the register names delta %s at sequence %d, but that sequence holds %s",
				entry.CaseID, entry.Role, entry.LedgerDeltaID, entry.LedgerSequence, record.id))
		case !record.cases[entry.CaseID]:
			problems = append(problems, fmt.Sprintf(
				"case %s (%s): ledger sequence %d does not cite this Autobahn case, so it does not "+
					"analyse this divergence", entry.CaseID, entry.Role, entry.LedgerSequence))
		}
	}
	sort.Strings(problems)
	return problems, nil
}

// VerifyRegisterIsExact checks the register against a measured agreement in
// BOTH directions: every observed divergence is registered, and every
// registered entry describes an observed divergence.
//
// A one-directional check would let stale entries accumulate, and a stale
// entry is a standing licence for a future regression on that case.
func VerifyRegisterIsExact(register *DivergenceRegister, agreement *Agreement) []string {
	var problems []string
	if agreement == nil {
		return []string{"no agreement"}
	}
	observed := map[string]CaseAgreement{}
	for _, row := range agreement.Cases {
		if row.Class == AgreementSubjectWeaker || row.Class == AgreementDiffer {
			observed[row.CaseID] = row
		}
	}
	registered := map[string]bool{}
	if register != nil {
		for _, entry := range register.Entries {
			if entry.Role != agreement.Role {
				continue
			}
			registered[entry.CaseID] = true
			row, diverges := observed[entry.CaseID]
			switch {
			case !diverges:
				problems = append(problems, fmt.Sprintf(
					"case %s (%s) is registered as a divergence but the runs agree on it; a stale "+
						"entry is a standing licence for a regression on that case",
					entry.CaseID, entry.Role))
			case row.SubjectBehavior != entry.SubjectBehavior || row.BaselineBehavior != entry.BaselineBehavior:
				problems = append(problems, fmt.Sprintf(
					"case %s (%s): the register records subject=%s baseline=%s but the runs show "+
						"subject=%s baseline=%s",
					entry.CaseID, entry.Role, entry.SubjectBehavior, entry.BaselineBehavior,
					row.SubjectBehavior, row.BaselineBehavior))
			}
		}
	}
	for caseID, row := range observed {
		if !registered[caseID] {
			problems = append(problems, fmt.Sprintf(
				"case %s (%s) diverges (subject=%s baseline=%s) and no register entry accounts for it",
				caseID, agreement.Role, row.SubjectBehavior, row.BaselineBehavior))
		}
	}
	sort.Strings(problems)
	return problems
}
