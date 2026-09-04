package divergencesweep

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// DocumentSchemaVersion is the version of the emitted evidence document.
const DocumentSchemaVersion = "1.0.0"

// DocumentEntityType names the artifact in the evidence tree.
const DocumentEntityType = "ObservedCloseDivergenceSweep"

// Document is the committed sweep artifact. Every number in it is recomputed
// from the report bytes; the prose fields (mechanism, recommendation, why) are
// authored, and the case sets those fields talk about are not.
type Document struct {
	SchemaVersion string `json:"schema_version"`
	EntityType    string `json:"entity_type"`
	Note          string `json:"note"`

	RecomputedFrom   Provenance     `json:"recomputed_from"`
	FieldPartition   FieldPartition `json:"field_partition"`
	DimensionCatalog []DimensionDoc `json:"dimension_catalog"`
	Measurements     []RoleDoc      `json:"measurements"`
	Accounting       Accounting     `json:"difference_accounting"`
	Classes          []ClassDoc     `json:"divergence_classes"`
}

// Provenance records what was read and what was checked before reading it.
type Provenance struct {
	EvidenceRoot    string   `json:"evidence_root"`
	DigestManifest  string   `json:"digest_manifest"`
	PinnedFileCount int      `json:"pinned_file_count"`
	RunID           string   `json:"run_id"`
	SubjectCommit   string   `json:"subject_commit"`
	CapturedAt      string   `json:"captured_at"`
	Legs            []LegDoc `json:"legs"`
	CrossChecks     []string `json:"cross_checks"`
	ScopeLimits     []string `json:"scope_limits"`
}

// LegDoc names one leg as it was actually loaded.
type LegDoc struct {
	Peer        string `json:"peer"`
	Directory   string `json:"directory"`
	SubjectRole string `json:"subject_role"`
	Agent       string `json:"agent"`
	CaseCount   int    `json:"case_count"`
}

// FieldPartition proves every key the reports carry was classified.
type FieldPartition struct {
	ObservedFieldCount int                `json:"observed_field_count"`
	ObservedFields     []string           `json:"observed_fields"`
	Compared           []string           `json:"compared"`
	Invariant          []string           `json:"invariant"`
	NotComparable      []NotComparableDoc `json:"not_comparable"`
	SumsTo             string             `json:"sums_to"`
}

// NotComparableDoc records a field and why it cannot be compared verbatim.
type NotComparableDoc struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

// DimensionDoc describes one comparison.
type DimensionDoc struct {
	Name        string `json:"name"`
	Group       string `json:"group"`
	SourceField string `json:"source_field,omitempty"`
	Derived     bool   `json:"derived,omitempty"`
	Meaning     string `json:"meaning"`
}

// RoleDoc is one subject role's measurements.
type RoleDoc struct {
	SubjectRole string          `json:"subject_role"`
	Leg         string          `json:"leg"`
	PortAgent   string          `json:"port_agent"`
	JavaAgent   string          `json:"java_agent"`
	CaseCount   int             `json:"case_count"`
	Groups      []GroupMeas     `json:"dimension_groups"`
	Dimensions  []DimensionMeas `json:"dimensions"`
}

// GroupMeas partitions the case set by whether the two subjects agreed on
// EVERY dimension in one group. It is the number a reader wants first: how
// many of the 247 cases close the same way in the port as in shipped Java.
type GroupMeas struct {
	Group                         string   `json:"group"`
	Dimensions                    []string `json:"dimensions"`
	CasesAgreeingOnEveryDimension int      `json:"cases_agreeing_on_every_dimension"`
	CasesDifferingSomewhere       int      `json:"cases_differing_on_at_least_one"`
	PartitionSum                  int      `json:"partition_sum"`
	AgreeingCases                 []string `json:"agreeing_cases"`
}

// DimensionMeas is one dimension's counts for one role. The four verdict
// counts partition the case set: agree + port_absent + java_absent +
// both_differ == case_count, asserted when the document is built.
type DimensionMeas struct {
	Dimension              string         `json:"dimension"`
	Agree                  int            `json:"agree"`
	PortAbsentJavaPresent  int            `json:"port_absent_java_present"`
	JavaAbsentPortPresent  int            `json:"java_absent_port_present"`
	BothPresentDiffer      int            `json:"both_present_differ"`
	TotalDifferences       int            `json:"total_differences"`
	PartitionSum           int            `json:"partition_sum"`
	DifferingCases         []string       `json:"differing_cases"`
	DistinctValuePairCount int            `json:"distinct_value_pair_count"`
	ValuePairs             []ValuePairDoc `json:"value_pairs,omitempty"`
	ValuePairsElided       bool           `json:"value_pairs_elided,omitempty"`
}

// ValuePairDoc is one observed (port value, java value) pair with its extent.
type ValuePairDoc struct {
	Port         string   `json:"port"`
	Java         string   `json:"java"`
	Verdict      string   `json:"verdict"`
	CaseCount    int      `json:"case_count"`
	ExampleCases []string `json:"example_cases"`
}

// Accounting proves every measured difference is attributed to a class.
type Accounting struct {
	TotalDifferences int `json:"total_differences"`
	ClaimedByAClass  int `json:"claimed_by_a_class"`
	Unclaimed        int `json:"unclaimed"`
	// ClaimSum is the sum of the per-class claims. It exceeds
	// ClaimedByAClass when two classes explain the same difference, which is
	// allowed and recorded rather than hidden.
	ClaimSum           int      `json:"class_claim_sum"`
	ClaimedTwice       int      `json:"differences_claimed_by_more_than_one_class"`
	ClaimedTwiceDetail []string `json:"differences_claimed_by_more_than_one_class_detail,omitempty"`
	UnclaimedExamples  []string `json:"unclaimed_examples,omitempty"`
	ZeroDivergenceDims []string `json:"dimensions_with_zero_divergence"`
}

// ClassDoc is one named divergence class with its measured extent.
type ClassDoc struct {
	ID             string `json:"id"`
	Title          string `json:"title"`
	SelectedOn     string `json:"selected_on"`
	Direction      string `json:"direction"`
	Mechanism      string `json:"mechanism"`
	JavaCitation   string `json:"java_citation"`
	PortSite       string `json:"port_site"`
	Recommendation string `json:"recommendation"`
	Why            string `json:"why"`
	// ProposedLedgerSubjectRef names the draft record under
	// drafts/ledger-proposals/ that carries this class, and LandedLedgerSequence
	// is where the committed behavior-delta ledger carries it (0 while it has
	// not landed). The pair is cross-checked against the ledger in both
	// directions; see ClassSpec.
	ProposedLedgerSubjectRef string `json:"proposed_ledger_subject_ref,omitempty"`
	LandedLedgerSequence     int    `json:"landed_ledger_sequence,omitempty"`
	// ExistingLedgerSubjectRef names the committed record that already
	// carries this class, asserted present at ExistingLedgerSequence.
	ExistingLedgerSubjectRef string              `json:"existing_ledger_subject_ref,omitempty"`
	ExistingLedgerSequence   int                 `json:"existing_ledger_sequence,omitempty"`
	CaseCounts               map[string]int      `json:"case_counts_by_subject_role"`
	Cases                    map[string][]string `json:"cases_by_subject_role"`
	Explains                 []string            `json:"explains_dimensions"`
	ClaimedDiffs             int                 `json:"claimed_differences"`
}

// valuePairLimit bounds how many distinct value pairs a dimension quotes.
const valuePairLimit = 64

// exampleCaseLimit bounds how many case identities a value pair quotes. The
// exhaustive per-dimension case list is in DifferingCases; these are only for
// reading.
const exampleCaseLimit = 6

// Build recomputes the whole document from a sweep.
func Build(sweep *Sweep) (*Document, error) {
	runID, err := os.ReadFile(filepath.Join(sweep.Root, EvidenceRoot, "run-id"))
	if err != nil {
		return nil, fmt.Errorf("run id: %w", err)
	}
	identityBytes, err := os.ReadFile(filepath.Join(sweep.Root, EvidenceRoot, "provenance/source-identity.json"))
	if err != nil {
		return nil, fmt.Errorf("source identity: %w", err)
	}
	var identity struct {
		CommitSHA struct {
			Value string `json:"value"`
		} `json:"commit_sha"`
		CapturedAt string `json:"captured_at"`
	}
	if err := decodeJSON(identityBytes, &identity); err != nil {
		return nil, fmt.Errorf("source identity: %w", err)
	}

	document := &Document{
		SchemaVersion: DocumentSchemaVersion,
		EntityType:    DocumentEntityType,
		Note:          "Per-case Java-versus-port comparison on everything the Autobahn behaviour classes and the public-corpus differential do NOT compare: the close code the subject sent, the close reason it sent, which peer closed the TCP connection, and every other field the per-case reports make comparable. Recomputed from the committed report bytes by internal/divergencesweep on every run; the digest manifest is verified first, each leg's index.json is cross-checked against the per-case reports it indexes, and the recomputed behaviour classes are cross-checked against the independently produced comparison document. Numbers here are measurements of ONE run of ONE port build; the prose recommendations are proposals, and nothing here writes to the behavior-delta ledger.",
		RecomputedFrom: Provenance{
			EvidenceRoot:    EvidenceRoot,
			DigestManifest:  DigestManifestPath,
			PinnedFileCount: sweep.PinnedFileCount,
			RunID:           string(bytes.TrimSpace(runID)),
			SubjectCommit:   identity.CommitSHA.Value,
			CapturedAt:      identity.CapturedAt,
			CrossChecks: []string{
				"every file under the evidence root matches evidence/autobahn/native-digest-manifest.json in both directions (no edited file, no planted file)",
				"each leg's index.json agrees with the per-case report it names on behavior, behaviorClose, duration and remoteCloseCode",
				"each leg's subject role is derived from the reports' own isServer flag and must equal the role the leg is declared to hold",
				"the invariant fields (case identity, description, expectation, expected, expectedClose, isServer and the report-configuration flags) are byte-equal between the two subjects on every case, so the two legs demonstrably walked the same manifest",
				"the recomputed behavior and behaviorClose classes equal the independently produced comparison/java-vs-rust-per-case.json for all four (role, subject) combinations",
			},
			ScopeLimits: []string{
				"This is one run. Every count is what that run's reports say, not a property of the port in general.",
				"The port build measured is the ws-testee binary from commit " + identity.CommitSHA.Value + " on claude/us019-native-run, captured " + identity.CapturedAt + ". Mainline has moved since; a divergence measured here may already be addressed on a branch, and each class says what this sweep could establish about that.",
				"Coverage is bounded by the 247-case pinned Autobahn manifest and by what the suite's per-case report records. A divergence the suite does not observe is not measured here.",
			},
		},
	}
	for _, pair := range sweep.Pairs {
		document.RecomputedFrom.Legs = append(document.RecomputedFrom.Legs,
			LegDoc{Peer: "rust", Directory: pair.Leg, SubjectRole: pair.SubjectRole, Agent: pair.Port.Agent, CaseCount: len(pair.IDs)},
			LegDoc{Peer: "java", Directory: pair.Leg, SubjectRole: pair.SubjectRole, Agent: pair.Java.Agent, CaseCount: len(pair.IDs)},
		)
	}

	notComparable := make([]NotComparableDoc, 0, len(NotComparableFields))
	for _, entry := range NotComparableFields {
		notComparable = append(notComparable, NotComparableDoc{Field: entry.Field, Reason: entry.Reason})
	}
	compared := ComparedFields()
	invariant := append([]string(nil), InvariantFields...)
	sort.Strings(invariant)
	document.FieldPartition = FieldPartition{
		ObservedFieldCount: len(sweep.ObservedFields),
		ObservedFields:     sweep.ObservedFields,
		Compared:           compared,
		Invariant:          invariant,
		NotComparable:      notComparable,
		SumsTo: fmt.Sprintf("%d compared + %d invariant + %d not-comparable = %d observed",
			len(compared), len(invariant), len(notComparable),
			len(compared)+len(invariant)+len(notComparable)),
	}
	if len(compared)+len(invariant)+len(notComparable) != len(sweep.ObservedFields) {
		return nil, fmt.Errorf("field partition does not sum: %s vs %d observed",
			document.FieldPartition.SumsTo, len(sweep.ObservedFields))
	}

	for _, dimension := range Dimensions() {
		document.DimensionCatalog = append(document.DimensionCatalog, DimensionDoc{
			Name:        dimension.Name,
			Group:       dimension.Group,
			SourceField: dimension.Field,
			Derived:     dimension.Derive != nil,
			Meaning:     dimension.Meaning,
		})
	}

	for _, pair := range sweep.Pairs {
		role := RoleDoc{
			SubjectRole: pair.SubjectRole,
			Leg:         pair.Leg,
			PortAgent:   pair.Port.Agent,
			JavaAgent:   pair.Java.Agent,
			CaseCount:   len(pair.IDs),
		}
		for _, dimension := range Dimensions() {
			differences := sweep.DifferencesByRoleDimension(pair.SubjectRole, dimension.Name)
			measurement := DimensionMeas{Dimension: dimension.Name}
			pairsByKey := map[string]*ValuePairDoc{}
			var order []string
			for _, difference := range differences {
				switch difference.Verdict {
				case VerdictPortAbsent:
					measurement.PortAbsentJavaPresent++
				case VerdictJavaAbsent:
					measurement.JavaAbsentPortPresent++
				case VerdictBothDiffer:
					measurement.BothPresentDiffer++
				default:
					return nil, fmt.Errorf("dimension %s: unexpected verdict %q", dimension.Name, difference.Verdict)
				}
				measurement.DifferingCases = append(measurement.DifferingCases, difference.CaseID)
				key := render(difference.PortValue) + "\x00" + render(difference.JavaValue)
				entry, ok := pairsByKey[key]
				if !ok {
					entry = &ValuePairDoc{
						Port:    render(difference.PortValue),
						Java:    render(difference.JavaValue),
						Verdict: string(difference.Verdict),
					}
					pairsByKey[key] = entry
					order = append(order, key)
				}
				entry.CaseCount++
				if len(entry.ExampleCases) < exampleCaseLimit {
					entry.ExampleCases = append(entry.ExampleCases, difference.CaseID)
				}
			}
			sort.Strings(measurement.DifferingCases)
			measurement.TotalDifferences = len(differences)
			measurement.Agree = len(pair.IDs) - measurement.TotalDifferences
			measurement.PartitionSum = measurement.Agree + measurement.PortAbsentJavaPresent +
				measurement.JavaAbsentPortPresent + measurement.BothPresentDiffer
			if measurement.PartitionSum != len(pair.IDs) {
				return nil, fmt.Errorf("%s role, dimension %s: verdict counts sum to %d, not the %d cases walked",
					pair.SubjectRole, dimension.Name, measurement.PartitionSum, len(pair.IDs))
			}
			measurement.DistinctValuePairCount = len(order)
			if len(order) <= valuePairLimit {
				sort.Strings(order)
				for _, key := range order {
					measurement.ValuePairs = append(measurement.ValuePairs, *pairsByKey[key])
				}
			} else {
				measurement.ValuePairsElided = true
			}
			role.Dimensions = append(role.Dimensions, measurement)
		}
		for _, group := range []string{"close", "protocol", "handshake"} {
			var names []string
			differing := map[string]bool{}
			for _, dimension := range Dimensions() {
				if dimension.Group != group {
					continue
				}
				names = append(names, dimension.Name)
				for _, difference := range sweep.DifferencesByRoleDimension(pair.SubjectRole, dimension.Name) {
					differing[difference.CaseID] = true
				}
			}
			if len(names) == 0 {
				return nil, fmt.Errorf("dimension group %q has no dimensions", group)
			}
			var agreeing []string
			for _, caseID := range pair.IDs {
				if !differing[caseID] {
					agreeing = append(agreeing, caseID)
				}
			}
			measurement := GroupMeas{
				Group:                         group,
				Dimensions:                    names,
				CasesAgreeingOnEveryDimension: len(agreeing),
				CasesDifferingSomewhere:       len(differing),
				PartitionSum:                  len(agreeing) + len(differing),
				AgreeingCases:                 agreeing,
			}
			if measurement.PartitionSum != len(pair.IDs) {
				return nil, fmt.Errorf("%s role, group %s: %d agreeing + %d differing != %d cases",
					pair.SubjectRole, group, len(agreeing), len(differing), len(pair.IDs))
			}
			role.Groups = append(role.Groups, measurement)
		}
		document.Measurements = append(document.Measurements, role)
	}

	// A dimension counts as zero-divergence only if it is zero on BOTH roles.
	var zeroNames []string
	for _, dimension := range Dimensions() {
		zero := true
		for _, pair := range sweep.Pairs {
			if len(sweep.DifferencesByRoleDimension(pair.SubjectRole, dimension.Name)) != 0 {
				zero = false
			}
		}
		if zero {
			zeroNames = append(zeroNames, dimension.Name)
		}
	}

	claimed := map[string]bool{}
	claimants := map[string][]string{}
	byClass := map[string]map[string]map[string]bool{}
	for _, spec := range Classes() {
		cases, err := classCases(sweep, spec, byClass)
		if err != nil {
			return nil, err
		}
		asSets := map[string]map[string]bool{}
		total := 0
		counts := map[string]int{}
		for role, list := range cases {
			asSets[role] = map[string]bool{}
			for _, caseID := range list {
				asSets[role][caseID] = true
			}
			counts[role] = len(list)
			total += len(list)
		}
		byClass[spec.ID] = asSets
		if total == 0 {
			return nil, fmt.Errorf("class %s selects no case: a class that claims nothing is not a finding", spec.ID)
		}
		classDoc := ClassDoc{
			ID:                       spec.ID,
			Title:                    spec.Title,
			SelectedOn:               describeSelector(spec.Selector),
			Direction:                spec.Direction,
			Mechanism:                spec.Mechanism,
			JavaCitation:             spec.JavaCitation,
			PortSite:                 spec.PortSite,
			Recommendation:           string(spec.Recommendation),
			Why:                      spec.Why,
			ProposedLedgerSubjectRef: spec.ProposedLedgerSubjectRef,
			LandedLedgerSequence:     spec.LandedLedgerSequence,
			ExistingLedgerSubjectRef: spec.ExistingLedgerSubjectRef,
			ExistingLedgerSequence:   spec.ExistingLedgerSequence,
			CaseCounts:               counts,
			Cases:                    cases,
			Explains:                 spec.Explains,
		}
		for _, difference := range sweep.Differences {
			if !asSets[difference.SubjectRole][difference.CaseID] {
				continue
			}
			if !containsString(spec.Explains, difference.Dimension) {
				continue
			}
			claimed[difference.Key()] = true
			claimants[difference.Key()] = append(claimants[difference.Key()], spec.ID)
			classDoc.ClaimedDiffs++
		}
		document.Classes = append(document.Classes, classDoc)
	}

	accounting := Accounting{
		TotalDifferences:   len(sweep.Differences),
		ZeroDivergenceDims: zeroNames,
	}
	for _, class := range document.Classes {
		accounting.ClaimSum += class.ClaimedDiffs
	}
	for _, difference := range sweep.Differences {
		if claimed[difference.Key()] {
			accounting.ClaimedByAClass++
			if names := claimants[difference.Key()]; len(names) > 1 {
				accounting.ClaimedTwice++
				detail := fmt.Sprintf("%s role, case %s, dimension %s: claimed by",
					difference.SubjectRole, difference.CaseID, difference.Dimension)
				for _, name := range names {
					detail += " " + name
				}
				accounting.ClaimedTwiceDetail = append(accounting.ClaimedTwiceDetail, detail)
			}
			continue
		}
		accounting.Unclaimed++
		if len(accounting.UnclaimedExamples) < 20 {
			accounting.UnclaimedExamples = append(accounting.UnclaimedExamples,
				fmt.Sprintf("%s role, case %s, dimension %s: port %s, java %s",
					difference.SubjectRole, difference.CaseID, difference.Dimension,
					render(difference.PortValue), render(difference.JavaValue)))
		}
	}
	document.Accounting = accounting
	return document, nil
}

func containsString(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func describeSelector(selector Selector) string {
	text := "dimension " + selector.Dimension
	if len(selector.Verdicts) > 0 {
		text += ", verdict in ["
		for i, verdict := range selector.Verdicts {
			if i > 0 {
				text += " "
			}
			text += string(verdict)
		}
		text += "]"
	}
	if selector.PortValue != "" {
		text += ", port value " + selector.PortValue
	}
	if selector.JavaValue != "" {
		text += ", java value " + selector.JavaValue
	}
	if len(selector.Roles) > 0 {
		text += ", subject role in ["
		for i, role := range selector.Roles {
			if i > 0 {
				text += " "
			}
			text += role
		}
		text += "]"
	}
	for _, classID := range selector.ExcludeClassIDs {
		text += ", excluding cases claimed by " + classID
	}
	return text
}

// Marshal renders the document in the committed form: indented JSON with a
// trailing newline.
func Marshal(document *Document) ([]byte, error) {
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}
