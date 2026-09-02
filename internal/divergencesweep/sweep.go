package divergencesweep

import (
	"fmt"
	"sort"
)

// RolePair is the two legs that share a subject role: the port's and Java's.
type RolePair struct {
	SubjectRole string
	Leg         string
	Port        *Leg
	Java        *Leg
	IDs         []string
}

// Difference is one (role, dimension, case) triple where the two subjects
// produced different values.
type Difference struct {
	SubjectRole string
	Dimension   string
	CaseID      string
	Verdict     Verdict
	PortValue   any
	JavaValue   any
}

// Key identifies the difference for coverage accounting.
func (d Difference) Key() string {
	return d.SubjectRole + "\x00" + d.Dimension + "\x00" + d.CaseID
}

// Sweep is the whole recomputed comparison: both role pairs, every dimension,
// every case.
type Sweep struct {
	Root string
	// PinnedFileCount is how many files the digest manifest pinned and this
	// sweep re-verified before reading anything.
	PinnedFileCount int
	Pairs           []*RolePair
	// Differences is every non-AGREE triple, ordered by role, dimension, case.
	Differences []Difference
	// InvariantViolations are cases where the two legs disagreed on a field
	// that describes the case rather than the subject.
	InvariantViolations []string
	// ObservedFields is the union of report keys seen across all four legs.
	ObservedFields []string
}

// Run loads all four legs, verifies the evidence tree against its digest
// manifest first, and recomputes every dimension.
func Run(root string) (*Sweep, error) {
	pinned, err := VerifyEvidenceIntegrity(root)
	if err != nil {
		return nil, err
	}
	legs := map[string]*Leg{}
	observed := map[string]bool{}
	for _, spec := range Legs() {
		leg, err := LoadLeg(root, spec)
		if err != nil {
			return nil, err
		}
		legs[spec.Peer+"/"+spec.SubjectRole] = leg
		for _, caseID := range leg.IDs {
			for key := range leg.Cases[caseID] {
				observed[key] = true
			}
		}
	}
	if err := CrossCheckBehaviourClasses(root, legs); err != nil {
		return nil, err
	}
	sweep := &Sweep{Root: root, PinnedFileCount: pinned}
	for key := range observed {
		sweep.ObservedFields = append(sweep.ObservedFields, key)
	}
	sort.Strings(sweep.ObservedFields)
	if err := checkFieldPartition(sweep.ObservedFields); err != nil {
		return nil, err
	}

	for _, role := range []string{"server", "client"} {
		port := legs["rust/"+role]
		java := legs["java/"+role]
		if port == nil || java == nil {
			return nil, fmt.Errorf("subject role %s: missing a leg", role)
		}
		if len(port.IDs) != len(java.IDs) {
			return nil, fmt.Errorf("subject role %s: %d port cases, %d java cases",
				role, len(port.IDs), len(java.IDs))
		}
		for i, caseID := range port.IDs {
			if java.IDs[i] != caseID {
				return nil, fmt.Errorf("subject role %s: case sets differ at %s vs %s",
					role, caseID, java.IDs[i])
			}
		}
		pair := &RolePair{SubjectRole: role, Leg: port.Spec.Directory, Port: port, Java: java, IDs: port.IDs}
		sweep.Pairs = append(sweep.Pairs, pair)

		for _, caseID := range pair.IDs {
			for _, field := range InvariantFields {
				portValue := port.Cases[caseID][field]
				javaValue := java.Cases[caseID][field]
				if canonical(portValue) != canonical(javaValue) {
					sweep.InvariantViolations = append(sweep.InvariantViolations,
						fmt.Sprintf("%s role, case %s, field %s: port %s, java %s",
							role, caseID, field, render(portValue), render(javaValue)))
				}
			}
		}

		for _, dimension := range Dimensions() {
			for _, caseID := range pair.IDs {
				portValue, err := readDimension(dimension, port, port.Cases[caseID])
				if err != nil {
					return nil, fmt.Errorf("%s role, case %s, dimension %s (port): %w",
						role, caseID, dimension.Name, err)
				}
				javaValue, err := readDimension(dimension, java, java.Cases[caseID])
				if err != nil {
					return nil, fmt.Errorf("%s role, case %s, dimension %s (java): %w",
						role, caseID, dimension.Name, err)
				}
				verdict := classify(portValue, javaValue)
				if verdict == VerdictAgree {
					continue
				}
				sweep.Differences = append(sweep.Differences, Difference{
					SubjectRole: role,
					Dimension:   dimension.Name,
					CaseID:      caseID,
					Verdict:     verdict,
					PortValue:   portValue,
					JavaValue:   javaValue,
				})
			}
		}
	}
	if len(sweep.InvariantViolations) > 0 {
		return nil, fmt.Errorf("the two legs did not walk the same case manifest: %d invariant violations, first: %s",
			len(sweep.InvariantViolations), sweep.InvariantViolations[0])
	}
	return sweep, nil
}

func readDimension(dimension Dimension, leg *Leg, report map[string]any) (any, error) {
	if dimension.Derive != nil {
		return dimension.Derive(leg, report)
	}
	value, ok := report[dimension.Field]
	if !ok {
		return nil, fmt.Errorf("report has no field %q", dimension.Field)
	}
	return value, nil
}

// checkFieldPartition refuses a report whose key set is not exactly the union
// of the three declared groups. A key nobody classified is a hole in the
// comparison, and an unclassified key is exactly the kind of thing this sweep
// exists to stop going unnoticed.
func checkFieldPartition(observed []string) error {
	classified := map[string]string{}
	add := func(field, group string) error {
		if existing, duplicate := classified[field]; duplicate {
			return fmt.Errorf("field %q is classified as both %s and %s", field, existing, group)
		}
		classified[field] = group
		return nil
	}
	for _, field := range InvariantFields {
		if err := add(field, "invariant"); err != nil {
			return err
		}
	}
	for _, field := range ComparedFields() {
		if err := add(field, "compared"); err != nil {
			return err
		}
	}
	for _, entry := range NotComparableFields {
		if err := add(entry.Field, "not_comparable"); err != nil {
			return err
		}
	}
	seen := map[string]bool{}
	for _, field := range observed {
		seen[field] = true
		if _, ok := classified[field]; !ok {
			return fmt.Errorf("the reports carry field %q, which this sweep does not classify as compared, invariant or not-comparable", field)
		}
	}
	for field := range classified {
		if !seen[field] {
			return fmt.Errorf("this sweep classifies field %q, which the reports do not carry", field)
		}
	}
	return nil
}

// DifferencesByRoleDimension groups the differences for the document.
func (s *Sweep) DifferencesByRoleDimension(role, dimension string) []Difference {
	var out []Difference
	for _, difference := range s.Differences {
		if difference.SubjectRole == role && difference.Dimension == dimension {
			out = append(out, difference)
		}
	}
	return out
}

// CaseIDsWithVerdict returns, for one role and dimension, the sorted case
// identities carrying the given verdict.
func (s *Sweep) CaseIDsWithVerdict(role, dimension string, verdict Verdict) []string {
	var out []string
	for _, difference := range s.Differences {
		if difference.SubjectRole == role && difference.Dimension == dimension && difference.Verdict == verdict {
			out = append(out, difference.CaseID)
		}
	}
	sort.Strings(out)
	return out
}
