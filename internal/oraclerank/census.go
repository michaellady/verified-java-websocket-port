package oraclerank

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/michaellady/verified-java-websocket-port/internal/divergencesweep"
)

// Committed artifacts this census reads. Every one is hashed into the emitted
// document, so a census that read different bytes than the one committed is a
// document mismatch rather than a silent difference.
const (
	AutobahnEvidenceRoot       = divergencesweep.EvidenceRoot
	AutobahnDigestManifestPath = divergencesweep.DigestManifestPath
	AutobahnComparisonPath     = divergencesweep.ComparisonPath
	AutobahnExpectedCaseCount  = divergencesweep.ExpectedCaseCount

	PublicCorpusPath         = "corpora/public/scenarios.jsonl"
	PublicCorpusManifestPath = "corpora/public/manifest.json"
	HandshakeCorpusPath      = "corpora/handshake/cases.jsonl"

	HandshakeLiveMappingPath = "evidence/us005-handshake-live-mapping.json"
	RFCDivergenceCensusPath  = "evidence/us005-public-rfc-divergence-census.json"
	CandidatePublicProofPath = "evidence/us005-candidate-public-proof.json"

	JavaArmPath = "evidence/differential-regression/java-arm.jsonl"
	RustArmPath = "evidence/differential-regression/rust-arm.jsonl"

	RustPublicTranscriptPath = "rust/ws-oracle-harness/baseline/borrow-batch-c-public-transcript.jsonl"
	RustPublicBaselinePath   = "rust/ws-oracle-harness/baseline/borrow-batch-c-public-baseline.json"
)

// Family identities.
const (
	FamilyAutobahn    = "autobahn-behavior-class"
	FamilyHandshake   = "handshake-verdict"
	FamilyPublicState = "public-corpus-ready-state"
	FamilyDiffProbe   = "differential-regression-probe"
)

// PublicCorpusSize and HandshakeCorpusSize are asserted, never assumed. A tier
// that has grown or shrunk is an error: the census would otherwise silently
// cover less than it claims.
const (
	PublicCorpusSize    = 74
	HandshakeCorpusSize = 49
	DiffProbeCount      = 23
)

// SourceStrength says how one rank's opinions inside one family are attached
// to bytes. It is deliberately finer than Strength: a rank can be content-bound
// in one family and a recorded reading in another, and averaging those into a
// single label is how a rank comes to look better attached than it is.
type SourceStrength string

const (
	// SourceContent means the opinions are read from bytes the oracle itself
	// produced: a suite report, an oracle process transcript.
	SourceContent SourceStrength = "CONTENT"
	// SourceRecordedReading means the opinions are read from a committed
	// human reading of the oracle or of a normative text.
	SourceRecordedReading SourceStrength = "RECORDED_READING"
	// SourceAggregateDerived means the per-proposition opinion is deduced
	// from a committed CLEAN-SWEEP aggregate plus a per-proposition
	// expectation. The deduction is only valid under a clean sweep, and the
	// census refuses to make it when the aggregate is not one.
	SourceAggregateDerived SourceStrength = "AGGREGATE_DERIVED"
	// SourceAbsent means no committed artifact carries this rank's opinion
	// in this family, so the rank abstains on every proposition in it.
	SourceAbsent SourceStrength = "ABSENT"
)

// RankSource records, per family and rank, where the opinions came from and
// which BYTES they came from. ArtifactGroup is what makes the independence
// probe interpretable: independence is a property of a PAIR, not of a rank, so
// each rank names the body of evidence its verdicts vary with, and two ranks
// sharing a group cannot be compared for independence. Reporting agreement
// inside a shared group would be an artifact of the derivation, not evidence.
type RankSource struct {
	Rank     Rank           `json:"rank"`
	RankName string         `json:"rank_name"`
	Strength SourceStrength `json:"strength"`
	Paths    []string       `json:"paths,omitempty"`
	// ArtifactGroup names the body of evidence this rank's verdicts vary
	// with, inside this family. Two ranks with the same group are not
	// independently sourced from each other. It is empty when the rank
	// abstains throughout the family.
	ArtifactGroup string `json:"artifact_group,omitempty"`
	Note          string `json:"note"`
}

// Family is one closed question space over one committed evidence set.
type Family struct {
	ID           string        `json:"family_id"`
	Question     string        `json:"question"`
	VerdictSpace []string      `json:"verdict_space"`
	RankSources  []RankSource  `json:"rank_sources"`
	Propositions []Proposition `json:"-"`
	CrossChecks  []string      `json:"cross_checks"`
}

// Census reads every committed evidence set this package binds and returns the
// families with their propositions. It fails closed: a missing artifact, a
// corpus that is not the size it should be, a cross-check that does not hold,
// or an aggregate that is not a clean sweep is an error rather than a smaller
// census.
func Census(root string) ([]Family, error) {
	var families []Family

	autobahn, err := censusAutobahn(root)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", FamilyAutobahn, err)
	}
	families = append(families, autobahn)

	handshake, err := censusHandshake(root)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", FamilyHandshake, err)
	}
	families = append(families, handshake)

	publicState, err := censusPublicState(root)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", FamilyPublicState, err)
	}
	families = append(families, publicState)

	diffProbe, err := censusDiffProbe(root)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", FamilyDiffProbe, err)
	}
	families = append(families, diffProbe)

	seen := map[string]bool{}
	for _, f := range families {
		for _, p := range f.Propositions {
			if seen[p.ID] {
				return nil, fmt.Errorf("proposition id %s appears twice across families", p.ID)
			}
			seen[p.ID] = true
		}
	}
	return families, nil
}

// ---------------------------------------------------------------------------
// Family A: Autobahn behaviour class. Ranks 2, 4 and 5, all content-bound, from
// three separately written artifact sets.
// ---------------------------------------------------------------------------

func censusAutobahn(root string) (Family, error) {
	pinned, err := divergencesweep.VerifyEvidenceIntegrity(root)
	if err != nil {
		return Family{}, fmt.Errorf("evidence integrity: %w", err)
	}

	byPeerRole := map[[2]string]*divergencesweep.Leg{}
	for _, spec := range divergencesweep.Legs() {
		leg, err := divergencesweep.LoadLeg(root, spec)
		if err != nil {
			return Family{}, err
		}
		byPeerRole[[2]string{spec.Peer, spec.SubjectRole}] = leg
	}

	roles := []string{"client", "server"}
	var caseIDs []string
	if leg, ok := byPeerRole[[2]string{"java", "server"}]; ok {
		caseIDs = append(caseIDs, leg.IDs...)
	}
	sortCaseIDs(caseIDs)
	if len(caseIDs) != AutobahnExpectedCaseCount {
		return Family{}, fmt.Errorf("leg holds %d cases, want %d", len(caseIDs), AutobahnExpectedCaseCount)
	}

	f := Family{
		ID: FamilyAutobahn,
		Question: "On this Autobahn case, in this subject role, which behaviour class does the subject exhibit? " +
			"Rank two's verdict is the class the suite's own per-case `expected` map endorses; ranks four and five are the classes the suite graded the pinned Java and the Rust port at.",
		VerdictSpace: []string{"OK", "NON-STRICT", "FAILED", "UNIMPLEMENTED", "INFORMATIONAL"},
		RankSources: []RankSource{
			{
				Rank: RankAutobahnInScope, RankName: RankAutobahnInScope.String(), Strength: SourceContent,
				Paths:         []string{AutobahnEvidenceRoot + "/{java,rust}/{fuzzingclient,fuzzingserver}-run1/cases/*.json (`expected` map)"},
				ArtifactGroup: "autobahn-case-definition",
				Note: "The suite writes its own `expected` map into every per-case report: behaviour class to the event sequences that class admits. The rank-two verdict is the strongest arm that map declares. The map is a property of the CASE, not of the subject, and the census asserts that: the Java-leg and Rust-leg maps must be byte-equal on all " +
					"494 (case, role) pairs, so rank two's verdict is confirmed by two separately written report sets before it is used.",
			},
			{
				Rank: RankJavaObservation, RankName: RankJavaObservation.String(), Strength: SourceContent,
				Paths:         []string{AutobahnEvidenceRoot + "/java/fuzzingclient-run1", AutobahnEvidenceRoot + "/java/fuzzingserver-run1"},
				ArtifactGroup: "autobahn-java-leg-behavior",
				Note:          "The `behavior` field the suite graded the pinned Java-WebSocket 1.6.0 process at, read from that leg's own per-case report bytes.",
			},
			{
				Rank: RankRustObservation, RankName: RankRustObservation.String(), Strength: SourceContent,
				Paths:         []string{AutobahnEvidenceRoot + "/rust/fuzzingclient-run1", AutobahnEvidenceRoot + "/rust/fuzzingserver-run1"},
				ArtifactGroup: "autobahn-rust-leg-behavior",
				Note:          "The `behavior` field the suite graded the Rust port at, read from that leg's own per-case report bytes.",
			},
			{
				Rank: RankRFC6455, RankName: RankRFC6455.String(), Strength: SourceAbsent,
				Note: "No committed artifact maps an Autobahn case to an RFC 6455 clause verdict, so rank one abstains on every proposition in this family.",
			},
			{
				Rank: RankNeutralExpectation, RankName: RankNeutralExpectation.String(), Strength: SourceAbsent,
				Note: "The neutral corpora are scenario-shaped and share no identity with Autobahn case ids, so rank three abstains on every proposition in this family.",
			},
		},
		CrossChecks: []string{
			fmt.Sprintf("the digest manifest at %s was verified in both directions over %d pinned files before any report was read", AutobahnDigestManifestPath, pinned),
			"each leg's index.json behaviour and behaviorClose were bound to the per-case report they index (divergencesweep.LoadLeg)",
			"the suite's `expected` map was asserted byte-equal between the Java leg and the Rust leg on every (case, role) pair",
			"whether a case is graded INFORMATIONAL was asserted to agree between the Java leg and the Rust leg on every (case, role) pair",
			fmt.Sprintf("the recomputed per-case Java and Rust behaviour classes were cross-checked against the independently produced %s", AutobahnComparisonPath),
		},
	}

	comparison, err := readAutobahnComparison(root)
	if err != nil {
		return Family{}, err
	}

	for _, role := range roles {
		javaLeg := byPeerRole[[2]string{"java", role}]
		rustLeg := byPeerRole[[2]string{"rust", role}]
		if javaLeg == nil || rustLeg == nil {
			return Family{}, fmt.Errorf("role %s: missing a leg", role)
		}
		for _, caseID := range caseIDs {
			javaReport, ok := javaLeg.Cases[caseID]
			if !ok {
				return Family{}, fmt.Errorf("role %s case %s: absent from the Java leg", role, caseID)
			}
			rustReport, ok := rustLeg.Cases[caseID]
			if !ok {
				return Family{}, fmt.Errorf("role %s case %s: absent from the Rust leg", role, caseID)
			}

			javaBehavior, err := reportString(javaReport, "behavior")
			if err != nil {
				return Family{}, fmt.Errorf("role %s case %s java: %w", role, caseID, err)
			}
			rustBehavior, err := reportString(rustReport, "behavior")
			if err != nil {
				return Family{}, fmt.Errorf("role %s case %s rust: %w", role, caseID, err)
			}

			if got := comparison[[2]string{role, caseID}]; got != ([2]string{javaBehavior, rustBehavior}) {
				return Family{}, fmt.Errorf(
					"role %s case %s: recomputed classes (java=%s rust=%s) disagree with %s (java=%s rust=%s)",
					role, caseID, javaBehavior, rustBehavior, AutobahnComparisonPath, got[0], got[1])
			}

			javaExpected, err := canonicalExpectedMap(javaReport)
			if err != nil {
				return Family{}, fmt.Errorf("role %s case %s java: %w", role, caseID, err)
			}
			rustExpected, err := canonicalExpectedMap(rustReport)
			if err != nil {
				return Family{}, fmt.Errorf("role %s case %s rust: %w", role, caseID, err)
			}
			if javaExpected != rustExpected {
				return Family{}, fmt.Errorf(
					"role %s case %s: the suite's `expected` map differs between legs (java=%s rust=%s); rank two's verdict is supposed to be a property of the case",
					role, caseID, javaExpected, rustExpected)
			}

			javaInformational := javaBehavior == "INFORMATIONAL"
			rustInformational := rustBehavior == "INFORMATIONAL"
			if javaInformational != rustInformational {
				return Family{}, fmt.Errorf(
					"role %s case %s: the legs disagree on whether the case is graded INFORMATIONAL (java=%s rust=%s)",
					role, caseID, javaBehavior, rustBehavior)
			}

			suiteOpinion := Opinion{
				Rank:   RankAutobahnInScope,
				Source: fmt.Sprintf("%s/{java,rust}/*-run1/cases/<case %s>#/expected", AutobahnEvidenceRoot, caseID),
			}
			endorsed, hasEndorsed := endorsedArm(javaExpected)
			switch {
			case javaInformational:
				suiteOpinion.Abstains = true
				suiteOpinion.AbstainReason = "the suite graded this case INFORMATIONAL on both legs; it declares no pass/fail here"
			case !hasEndorsed:
				suiteOpinion.Abstains = true
				suiteOpinion.AbstainReason = "the suite's `expected` map declares no behaviour-class arm for this case"
			default:
				suiteOpinion.Verdict = endorsed
			}

			f.Propositions = append(f.Propositions, Proposition{
				ID:       fmt.Sprintf("%s/%s/%s", FamilyAutobahn, role, caseID),
				Family:   FamilyAutobahn,
				Question: fmt.Sprintf("Autobahn case %s, subject role %s: which behaviour class?", caseID, role),
				Opinions: []Opinion{
					suiteOpinion,
					{
						Rank:    RankJavaObservation,
						Verdict: javaBehavior,
						Source:  fmt.Sprintf("%s/java/*-run1/cases/<case %s>#/behavior", AutobahnEvidenceRoot, caseID),
					},
					{
						Rank:    RankRustObservation,
						Verdict: rustBehavior,
						Source:  fmt.Sprintf("%s/rust/*-run1/cases/<case %s>#/behavior", AutobahnEvidenceRoot, caseID),
					},
				},
			})
		}
	}

	want := 2 * AutobahnExpectedCaseCount
	if len(f.Propositions) != want {
		return Family{}, fmt.Errorf("built %d propositions, want %d", len(f.Propositions), want)
	}
	return f, nil
}

// endorsedArm returns the strongest behaviour class the suite's `expected` map
// declares for a case. The suite's own preference order is OK above NON-STRICT;
// an arm outside that closed set is an error, not a guess.
func endorsedArm(canonicalExpected string) (string, bool) {
	var arms map[string]any
	if err := json.Unmarshal([]byte(canonicalExpected), &arms); err != nil {
		return "", false
	}
	if _, ok := arms["OK"]; ok {
		return "OK", true
	}
	if _, ok := arms["NON-STRICT"]; ok {
		return "NON-STRICT", true
	}
	return "", false
}

func canonicalExpectedMap(report map[string]any) (string, error) {
	raw, ok := report["expected"]
	if !ok {
		return "", fmt.Errorf("report carries no `expected` map")
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return "", fmt.Errorf("encode `expected`: %w", err)
	}
	return string(encoded), nil
}

func reportString(report map[string]any, field string) (string, error) {
	value, ok := report[field].(string)
	if !ok || value == "" {
		return "", fmt.Errorf("report field %q is missing or not a string", field)
	}
	return value, nil
}

// readAutobahnComparison loads the independently produced per-case comparison
// as (role, case) -> (java behaviour, rust behaviour).
func readAutobahnComparison(root string) (map[[2]string][2]string, error) {
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(AutobahnComparisonPath)))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", AutobahnComparisonPath, err)
	}
	var doc struct {
		Cases []struct {
			CaseID             string `json:"case_id"`
			RustServerBehavior string `json:"rust_server_behavior"`
			JavaServerBehavior string `json:"java_server_behavior"`
			RustClientBehavior string `json:"rust_client_behavior"`
			JavaClientBehavior string `json:"java_client_behavior"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decode %s: %w", AutobahnComparisonPath, err)
	}
	if len(doc.Cases) != AutobahnExpectedCaseCount {
		return nil, fmt.Errorf("%s holds %d cases, want %d", AutobahnComparisonPath, len(doc.Cases), AutobahnExpectedCaseCount)
	}
	out := make(map[[2]string][2]string, 2*len(doc.Cases))
	for _, c := range doc.Cases {
		out[[2]string{"server", c.CaseID}] = [2]string{c.JavaServerBehavior, c.RustServerBehavior}
		out[[2]string{"client", c.CaseID}] = [2]string{c.JavaClientBehavior, c.RustClientBehavior}
	}
	return out, nil
}

// sortCaseIDs orders Autobahn case identities by their dotted numeric parts so
// 1.2.10 follows 1.2.9 rather than 1.2.1.
func sortCaseIDs(ids []string) {
	sort.Slice(ids, func(i, j int) bool { return lessCaseID(ids[i], ids[j]) })
}

func lessCaseID(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		if as[i] == bs[i] {
			continue
		}
		ai, aerr := parseUint(as[i])
		bi, berr := parseUint(bs[i])
		if aerr == nil && berr == nil {
			return ai < bi
		}
		return as[i] < bs[i]
	}
	return len(as) < len(bs)
}

func parseUint(s string) (uint64, error) {
	var n uint64
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("not numeric")
		}
		n = n*10 + uint64(r-'0')
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// Family B: handshake verdict. Rank one (a recorded RFC reading), rank three
// (the committed handshake corpus) and rank four (a recorded reading of the
// pinned Java sources). Rank five abstains: no per-case Rust handshake
// transcript is committed.
// ---------------------------------------------------------------------------

type handshakeCase struct {
	CaseID    string `json:"case_id"`
	Direction string `json:"direction"`
	Family    string `json:"family"`
	Expected  struct {
		Verdict    string   `json:"verdict"`
		RejectCode string   `json:"reject_code"`
		Basis      []string `json:"basis"`
	} `json:"expected"`
}

type handshakeMappingEntry struct {
	Direction      string `json:"direction"`
	Key            string `json:"key"`
	RFCVerdict     string `json:"rfc_verdict"`
	JavaObservable string `json:"java_observable"`
	Divergent      bool   `json:"divergent"`
	Condition      string `json:"condition"`
}

func censusHandshake(root string) (Family, error) {
	cases, err := readHandshakeCases(root)
	if err != nil {
		return Family{}, err
	}
	if len(cases) != HandshakeCorpusSize {
		return Family{}, fmt.Errorf("%s holds %d cases, want %d", HandshakeCorpusPath, len(cases), HandshakeCorpusSize)
	}
	mapping, err := readHandshakeMapping(root)
	if err != nil {
		return Family{}, err
	}

	// The mapping's own structure decides how much this family can ever
	// say, so it is asserted rather than described. Every entry the mapping
	// marks divergent from the RFC reading is exactly an entry whose Java
	// observable it records as `conditional`, and rank four abstains on
	// `conditional`. The consequence is that this family CANNOT exhibit a
	// rank-one-overrides-rank-four adjudication: on every outcome key where
	// the two are recorded as diverging, rank four declines to speak. If
	// that coincidence ever breaks, this assertion fails and the family's
	// stated reach has to be rewritten rather than quietly widened.
	divergent, conditional := 0, 0
	for key, e := range mapping {
		isConditional := e.JavaObservable == "conditional"
		if e.Divergent {
			divergent++
		}
		if isConditional {
			conditional++
		}
		if e.Divergent != isConditional {
			return Family{}, fmt.Errorf(
				"%s: entry %s/%s records divergent=%v and java_observable=%q; this family's reach is stated on the assumption that those coincide exactly",
				HandshakeLiveMappingPath, key[0], key[1], e.Divergent, e.JavaObservable)
		}
	}

	f := Family{
		ID:           FamilyHandshake,
		Question:     "On this committed handshake case, does the endpoint accept the head, reject it, or treat it as incomplete?",
		VerdictSpace: []string{"accept", "reject", "incomplete"},
		RankSources: []RankSource{
			{
				Rank: RankRFC6455, RankName: RankRFC6455.String(), Strength: SourceRecordedReading,
				Paths:         []string{HandshakeLiveMappingPath},
				ArtifactGroup: "handshake-live-mapping",
				Note:          "The `rfc_verdict` field of the committed handshake mapping: a human reading of RFC 6455 sections 1.3, 4.1 and 4.2, recorded per outcome key. The mapping's bytes are hashed on every run; the RFC text is not in this repository, so the reading itself is not re-derivable here. The same document also carries rank four, so this pair is NOT independently sourced and the independence probe declines to score it.",
			},
			{
				Rank: RankNeutralExpectation, RankName: RankNeutralExpectation.String(), Strength: SourceContent,
				Paths:         []string{HandshakeCorpusPath},
				ArtifactGroup: "handshake-corpus",
				Note:          "The committed handshake corpus's own `expected.verdict`, whose `basis` cites RFC 6455, RFC 9110 and RFC 9112 clauses directly. This tier's expectations are NOT the Java-mirroring reference model that produces the public tier's; they disagree with the Java observable on a large fraction of cases, which the independence probe measures rather than assumes.",
			},
			{
				Rank: RankJavaObservation, RankName: RankJavaObservation.String(), Strength: SourceRecordedReading,
				Paths:         []string{HandshakeLiveMappingPath},
				ArtifactGroup: "handshake-live-mapping",
				Note:          "The `java_observable` field of the same mapping: a reading of the pinned Java-WebSocket 1.6.0 SOURCES (its `basis` cites Draft_6455.java and WebSocketImpl.java by line), not a transcript of the Java process. Where the mapping records `conditional`, rank four abstains with the mapping's own condition text rather than the census inventing a resolution.",
			},
			{
				Rank: RankAutobahnInScope, RankName: RankAutobahnInScope.String(), Strength: SourceAbsent,
				Note: "The in-scope Autobahn selection does not exercise malformed handshake heads, so rank two abstains on every proposition in this family.",
			},
			{
				Rank: RankRustObservation, RankName: RankRustObservation.String(), Strength: SourceAbsent,
				Note: "NO per-case Rust handshake transcript is committed to this repository. corpora/handshake/manifest.json records execution_status LIVE_EXECUTED with a transcript sha256, but the transcript bytes are not here. Rank five therefore abstains on all 49 propositions, and this family cannot exercise AC2's final clause at all.",
			},
		},
		CrossChecks: []string{
			fmt.Sprintf("every one of the %d handshake cases resolved to an outcome key present in %s; an unmapped key is an error", HandshakeCorpusSize, HandshakeLiveMappingPath),
			"the mapping's rfc_verdict and java_observable were read as separate opinions and never reconciled by the census",
			fmt.Sprintf("the %d outcome keys the mapping marks divergent are EXACTLY the %d whose java_observable it records as `conditional`, asserted in both directions; rank four abstains on all of them, so this family cannot exhibit a rank-one-overrides-rank-four adjudication at all", divergent, conditional),
		},
	}

	for _, c := range cases {
		key, err := handshakeOutcomeKey(c)
		if err != nil {
			return Family{}, err
		}
		entry, ok := mapping[[2]string{c.Direction, key}]
		if !ok {
			return Family{}, fmt.Errorf("case %s: outcome key %q (%s) is not in %s", c.CaseID, key, c.Direction, HandshakeLiveMappingPath)
		}

		rfcOpinion := Opinion{
			Rank:   RankRFC6455,
			Source: fmt.Sprintf("%s#/entries[%s %s]/rfc_verdict", HandshakeLiveMappingPath, c.Direction, key),
		}
		if !isHandshakeVerdict(entry.RFCVerdict) {
			return Family{}, fmt.Errorf("case %s: mapping rfc_verdict %q is outside the verdict space", c.CaseID, entry.RFCVerdict)
		}
		rfcOpinion.Verdict = entry.RFCVerdict

		javaOpinion := Opinion{
			Rank:   RankJavaObservation,
			Source: fmt.Sprintf("%s#/entries[%s %s]/java_observable", HandshakeLiveMappingPath, c.Direction, key),
		}
		switch {
		case isHandshakeVerdict(entry.JavaObservable):
			javaOpinion.Verdict = entry.JavaObservable
		case entry.JavaObservable == "conditional":
			javaOpinion.Abstains = true
			javaOpinion.AbstainReason = "the mapping records the Java observable as conditional: " + firstLine(entry.Condition)
		default:
			return Family{}, fmt.Errorf("case %s: mapping java_observable %q is outside the verdict space", c.CaseID, entry.JavaObservable)
		}

		if !isHandshakeVerdict(c.Expected.Verdict) {
			return Family{}, fmt.Errorf("case %s: corpus verdict %q is outside the verdict space", c.CaseID, c.Expected.Verdict)
		}

		f.Propositions = append(f.Propositions, Proposition{
			ID:       fmt.Sprintf("%s/%s", FamilyHandshake, c.CaseID),
			Family:   FamilyHandshake,
			Question: fmt.Sprintf("Handshake case %s (%s, family %s): accept, reject or incomplete?", c.CaseID, c.Direction, c.Family),
			Opinions: []Opinion{
				rfcOpinion,
				{
					Rank:    RankNeutralExpectation,
					Verdict: c.Expected.Verdict,
					Source:  fmt.Sprintf("%s#<%s>/expected/verdict", HandshakeCorpusPath, c.CaseID),
				},
				javaOpinion,
				{
					Rank:          RankRustObservation,
					Abstains:      true,
					AbstainReason: "no per-case Rust handshake transcript is committed to this repository",
					Source:        HandshakeCorpusPath + " (no Rust arm)",
				},
			},
		})
	}
	return f, nil
}

func isHandshakeVerdict(v string) bool {
	return v == "accept" || v == "reject" || v == "incomplete"
}

func handshakeOutcomeKey(c handshakeCase) (string, error) {
	switch c.Expected.Verdict {
	case "accept":
		return "accept", nil
	case "incomplete":
		return "incomplete", nil
	case "reject":
		if c.Expected.RejectCode == "" {
			return "", fmt.Errorf("case %s rejects with no reject_code", c.CaseID)
		}
		return c.Expected.RejectCode, nil
	default:
		return "", fmt.Errorf("case %s: verdict %q is outside the verdict space", c.CaseID, c.Expected.Verdict)
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 220 {
		s = s[:220] + "..."
	}
	if s == "" {
		return "(the mapping records no condition text)"
	}
	return s
}

func readHandshakeCases(root string) ([]handshakeCase, error) {
	lines, err := readJSONLines(root, HandshakeCorpusPath)
	if err != nil {
		return nil, err
	}
	out := make([]handshakeCase, 0, len(lines))
	for i, line := range lines {
		var c handshakeCase
		if err := json.Unmarshal(line, &c); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", HandshakeCorpusPath, i+1, err)
		}
		out = append(out, c)
	}
	return out, nil
}

func readHandshakeMapping(root string) (map[[2]string]handshakeMappingEntry, error) {
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(HandshakeLiveMappingPath)))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", HandshakeLiveMappingPath, err)
	}
	var doc struct {
		Entries []handshakeMappingEntry `json:"entries"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decode %s: %w", HandshakeLiveMappingPath, err)
	}
	if len(doc.Entries) == 0 {
		return nil, fmt.Errorf("%s holds no entries", HandshakeLiveMappingPath)
	}
	out := make(map[[2]string]handshakeMappingEntry, len(doc.Entries))
	for _, e := range doc.Entries {
		key := [2]string{e.Direction, e.Key}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("%s maps %s/%s twice", HandshakeLiveMappingPath, e.Direction, e.Key)
		}
		out[key] = e
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Family C: public-corpus ready state. Rank one from the committed RFC
// divergence census, rank three from the corpus expectation, rank five from the
// committed Rust transcript, rank four deduced from a clean-sweep aggregate.
// ---------------------------------------------------------------------------

type publicScenario struct {
	ScenarioID        string `json:"scenario_id"`
	Family            string `json:"family"`
	ExpectationStatus string `json:"expectation_status"`
	Expected          struct {
		FinalState string `json:"final_state"`
	} `json:"expected"`
}

type rfcCensusEntry struct {
	ScenarioID            string   `json:"scenario_id"`
	Pointer               string   `json:"pointer"`
	Family                string   `json:"family"`
	RFCClauses            []string `json:"rfc_clauses"`
	RFCStrictExpectation  string   `json:"rfc_strict_expectation"`
	RecordedObservable    string   `json:"recorded_observable"`
	PortFollows           string   `json:"port_follows"`
	LedgerDeltaIdentifier string   `json:"ledger_delta_id"`
}

func censusPublicState(root string) (Family, error) {
	scenarios, err := readPublicScenarios(root)
	if err != nil {
		return Family{}, err
	}
	if len(scenarios) != PublicCorpusSize {
		return Family{}, fmt.Errorf("%s holds %d scenarios, want %d", PublicCorpusPath, len(scenarios), PublicCorpusSize)
	}

	// The rank-four deduction is only sound under a clean sweep. Both
	// aggregates are checked, and either one short of a clean sweep refuses
	// the deduction rather than weakening it.
	if err := requireCleanSweep(root, PublicCorpusManifestPath, "counts", PublicCorpusSize); err != nil {
		return Family{}, err
	}
	javaPassed, err := pristineJavaSweep(root)
	if err != nil {
		return Family{}, err
	}
	if javaPassed != PublicCorpusSize {
		return Family{}, fmt.Errorf("%s records the pristine Java arm at %d/%d; the rank-four deduction needs a clean sweep",
			CandidatePublicProofPath, javaPassed, PublicCorpusSize)
	}
	if err := requireRustPublicSweep(root); err != nil {
		return Family{}, err
	}

	rustState, err := readRustPublicTranscript(root)
	if err != nil {
		return Family{}, err
	}
	entries, err := readRFCDivergenceCensus(root)
	if err != nil {
		return Family{}, err
	}

	f := Family{
		ID:           FamilyPublicState,
		Question:     "After this public scenario runs, is the endpoint's ready state open or closed?",
		VerdictSpace: []string{"open", "closing", "closed"},
		RankSources: []RankSource{
			{
				Rank: RankRFC6455, RankName: RankRFC6455.String(), Strength: SourceRecordedReading,
				Paths:         []string{RFCDivergenceCensusPath},
				ArtifactGroup: "public-rfc-divergence-census",
				Note:          "The `rfc_strict_expectation` field of the committed RFC divergence census: a human reading of RFC 6455 sections 5.2, 7.1.7 and 7.4, recorded per scenario. Rank one abstains on scenarios the census does not enrol; the census's own `completeness` field states the class it is complete over.",
			},
			{
				Rank: RankNeutralExpectation, RankName: RankNeutralExpectation.String(), Strength: SourceContent,
				Paths:         []string{PublicCorpusPath},
				ArtifactGroup: "public-corpus-expectation",
				Note:          "The corpus's own `expected.final_state`. Every scenario records expectation_status REFERENCE_MODEL_DERIVED_PENDING_ORACLE_CONFIRMATION, and rank four in this family is deduced from that same expectation plus a clean-sweep aggregate, so ranks three and four here are NOT independently sourced and the independence probe declines to score that pair.",
			},
			{
				Rank: RankJavaObservation, RankName: RankJavaObservation.String(), Strength: SourceAggregateDerived,
				Paths:         []string{PublicCorpusManifestPath, CandidatePublicProofPath, PublicCorpusPath},
				ArtifactGroup: "public-corpus-expectation",
				Note:          "No per-scenario Java transcript for the public tier is committed. The per-scenario Java observation is DEDUCED: both aggregates record 74 executed, 74 passed, 0 failed against the pristine java-oracle, and under a clean sweep every scenario's observed final_state equals its recorded expectation. The census refuses this deduction when either aggregate is short of a clean sweep.",
			},
			{
				Rank: RankRustObservation, RankName: RankRustObservation.String(), Strength: SourceContent,
				Paths:         []string{RustPublicTranscriptPath, RustPublicBaselinePath},
				ArtifactGroup: "rust-public-transcript",
				Note:          "The committed per-scenario Rust transcript, read line by line: 74 records keyed by request_id, each carrying its own final_state. This is the one rank in this family read from per-case bytes the other ranks do not touch.",
			},
			{
				Rank: RankAutobahnInScope, RankName: RankAutobahnInScope.String(), Strength: SourceAbsent,
				Note: "Public scenarios share no identity with Autobahn case ids, so rank two abstains on every proposition in this family.",
			},
		},
		CrossChecks: []string{
			fmt.Sprintf("%s records executed=passed=%d, failed=0", PublicCorpusManifestPath, PublicCorpusSize),
			fmt.Sprintf("%s records the pristine java-oracle arm at %d/%d with evaluate_exit 0", CandidatePublicProofPath, javaPassed, PublicCorpusSize),
			fmt.Sprintf("%s records the Rust arm at %d/%d with exit_code 0", RustPublicBaselinePath, PublicCorpusSize, PublicCorpusSize),
			fmt.Sprintf("every scenario id in %s resolves to exactly one record in %s", PublicCorpusPath, RustPublicTranscriptPath),
			fmt.Sprintf("every scenario enrolled by %s carries a recorded_observable equal to the corpus expectation it cites", RFCDivergenceCensusPath),
		},
	}

	for _, s := range scenarios {
		if !isReadyState(s.Expected.FinalState) {
			return Family{}, fmt.Errorf("scenario %s: expected.final_state %q is outside the verdict space", s.ScenarioID, s.Expected.FinalState)
		}
		rustFinal, ok := rustState[s.ScenarioID]
		if !ok {
			return Family{}, fmt.Errorf("scenario %s: absent from %s", s.ScenarioID, RustPublicTranscriptPath)
		}
		if !isReadyState(rustFinal) {
			return Family{}, fmt.Errorf("scenario %s: Rust transcript final_state %q is outside the verdict space", s.ScenarioID, rustFinal)
		}

		rfcOpinion := Opinion{
			Rank:   RankRFC6455,
			Source: fmt.Sprintf("%s#/entries[%s]/rfc_strict_expectation", RFCDivergenceCensusPath, s.ScenarioID),
		}
		if entry, enrolled := entries[s.ScenarioID]; enrolled {
			verdict, err := strictStateVerdict(entry.RFCStrictExpectation)
			if err != nil {
				return Family{}, fmt.Errorf("scenario %s: %w", s.ScenarioID, err)
			}
			if entry.RecordedObservable != s.Expected.FinalState {
				return Family{}, fmt.Errorf(
					"scenario %s: %s records observable %q, the corpus expectation is %q",
					s.ScenarioID, RFCDivergenceCensusPath, entry.RecordedObservable, s.Expected.FinalState)
			}
			rfcOpinion.Verdict = verdict
		} else {
			rfcOpinion.Abstains = true
			rfcOpinion.AbstainReason = "not enrolled by the committed RFC divergence census; no committed reading states an RFC-strict ready state for this scenario"
		}

		f.Propositions = append(f.Propositions, Proposition{
			ID:       fmt.Sprintf("%s/%s", FamilyPublicState, s.ScenarioID),
			Family:   FamilyPublicState,
			Question: fmt.Sprintf("Public scenario %s (family %s): open or closed after the run?", s.ScenarioID, s.Family),
			Opinions: []Opinion{
				rfcOpinion,
				{
					Rank:    RankNeutralExpectation,
					Verdict: s.Expected.FinalState,
					Source:  fmt.Sprintf("%s#<%s>/expected/final_state", PublicCorpusPath, s.ScenarioID),
				},
				{
					Rank:    RankJavaObservation,
					Verdict: s.Expected.FinalState,
					Source:  fmt.Sprintf("deduced from the clean sweep in %s and %s plus %s#<%s>/expected/final_state", PublicCorpusManifestPath, CandidatePublicProofPath, PublicCorpusPath, s.ScenarioID),
				},
				{
					Rank:    RankRustObservation,
					Verdict: rustFinal,
					Source:  fmt.Sprintf("%s#<%s>/final_state", RustPublicTranscriptPath, s.ScenarioID),
				},
			},
		})
	}
	return f, nil
}

// strictStateVerdict reads the leading token of an rfc_strict_expectation
// sentence, which the committed census writes as "<state> — <reason>".
func strictStateVerdict(sentence string) (string, error) {
	head := sentence
	for _, sep := range []string{" — ", " - ", ":"} {
		if i := strings.Index(head, sep); i >= 0 {
			head = head[:i]
			break
		}
	}
	head = strings.TrimSpace(strings.ToLower(head))
	if !isReadyState(head) {
		return "", fmt.Errorf("rfc_strict_expectation %q does not begin with a ready state", sentence)
	}
	return head, nil
}

// isReadyState is the closed ready-state verdict space of the public tier,
// asserted against the committed corpus rather than assumed: the corpus carries
// open, closing and closed, and a fourth value is an error.
func isReadyState(v string) bool {
	return v == "open" || v == "closing" || v == "closed"
}

func readPublicScenarios(root string) ([]publicScenario, error) {
	lines, err := readJSONLines(root, PublicCorpusPath)
	if err != nil {
		return nil, err
	}
	out := make([]publicScenario, 0, len(lines))
	for i, line := range lines {
		var s publicScenario
		if err := json.Unmarshal(line, &s); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", PublicCorpusPath, i+1, err)
		}
		out = append(out, s)
	}
	return out, nil
}

type expectationStatusSummary struct {
	total    int
	dominant string
}

func publicExpectationStatuses(root string) (expectationStatusSummary, error) {
	scenarios, err := readPublicScenarios(root)
	if err != nil {
		return expectationStatusSummary{}, err
	}
	counts := map[string]int{}
	for _, s := range scenarios {
		counts[s.ExpectationStatus]++
	}
	summary := expectationStatusSummary{total: len(scenarios)}
	best := 0
	for status, n := range counts {
		if n > best || (n == best && status < summary.dominant) {
			best, summary.dominant = n, status
		}
	}
	if best != summary.total {
		return expectationStatusSummary{}, fmt.Errorf(
			"%s carries %d distinct expectation_status values; this binding states one and would misreport a mixed tier",
			PublicCorpusPath, len(counts))
	}
	return summary, nil
}

func readRustPublicTranscript(root string) (map[string]string, error) {
	lines, err := readJSONLines(root, RustPublicTranscriptPath)
	if err != nil {
		return nil, err
	}
	if len(lines) != PublicCorpusSize {
		return nil, fmt.Errorf("%s holds %d records, want %d", RustPublicTranscriptPath, len(lines), PublicCorpusSize)
	}
	out := make(map[string]string, len(lines))
	for i, line := range lines {
		var rec struct {
			RequestID  string `json:"request_id"`
			FinalState string `json:"final_state"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", RustPublicTranscriptPath, i+1, err)
		}
		if rec.RequestID == "" {
			return nil, fmt.Errorf("%s line %d: no request_id", RustPublicTranscriptPath, i+1)
		}
		if _, dup := out[rec.RequestID]; dup {
			return nil, fmt.Errorf("%s names %s twice", RustPublicTranscriptPath, rec.RequestID)
		}
		out[rec.RequestID] = rec.FinalState
	}
	return out, nil
}

func readRFCDivergenceCensus(root string) (map[string]rfcCensusEntry, error) {
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(RFCDivergenceCensusPath)))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", RFCDivergenceCensusPath, err)
	}
	var doc struct {
		Entries []rfcCensusEntry `json:"entries"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decode %s: %w", RFCDivergenceCensusPath, err)
	}
	if len(doc.Entries) == 0 {
		return nil, fmt.Errorf("%s holds no entries", RFCDivergenceCensusPath)
	}
	out := make(map[string]rfcCensusEntry, len(doc.Entries))
	for _, e := range doc.Entries {
		if _, dup := out[e.ScenarioID]; dup {
			return nil, fmt.Errorf("%s enrols %s twice", RFCDivergenceCensusPath, e.ScenarioID)
		}
		out[e.ScenarioID] = e
	}
	return out, nil
}

func requireCleanSweep(root, path, field string, want int) error {
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	counts, ok := doc[field].(map[string]any)
	if !ok {
		return fmt.Errorf("%s has no %q object", path, field)
	}
	get := func(name string) (int, error) {
		v, ok := counts[name].(float64)
		if !ok {
			return 0, fmt.Errorf("%s: %s.%s is missing or not a number", path, field, name)
		}
		return int(v), nil
	}
	executed, err := get("executed")
	if err != nil {
		return err
	}
	passed, err := get("passed")
	if err != nil {
		return err
	}
	failed, err := get("failed")
	if err != nil {
		return err
	}
	if executed != want || passed != want || failed != 0 {
		return fmt.Errorf("%s records executed=%d passed=%d failed=%d; the rank-four deduction is only sound under a clean sweep of %d/%d/0",
			path, executed, passed, failed, want, want)
	}
	return nil
}

func pristineJavaSweep(root string) (int, error) {
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(CandidatePublicProofPath)))
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", CandidatePublicProofPath, err)
	}
	var doc struct {
		Baseline struct {
			Report struct {
				Executed int `json:"executed"`
				Passed   int `json:"passed"`
				Failed   int `json:"failed"`
			} `json:"report"`
			EvaluateExit int `json:"evaluate_exit"`
		} `json:"pristine_separation_baseline"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return 0, fmt.Errorf("decode %s: %w", CandidatePublicProofPath, err)
	}
	r := doc.Baseline.Report
	if r.Executed == 0 {
		return 0, fmt.Errorf("%s carries no pristine_separation_baseline report", CandidatePublicProofPath)
	}
	if r.Failed != 0 || doc.Baseline.EvaluateExit != 0 {
		return 0, fmt.Errorf("%s records the pristine Java arm with failed=%d evaluate_exit=%d; the rank-four deduction needs a clean sweep",
			CandidatePublicProofPath, r.Failed, doc.Baseline.EvaluateExit)
	}
	return r.Passed, nil
}

func requireRustPublicSweep(root string) error {
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(RustPublicBaselinePath)))
	if err != nil {
		return fmt.Errorf("read %s: %w", RustPublicBaselinePath, err)
	}
	var doc struct {
		Report struct {
			Executed int `json:"executed"`
			Passed   int `json:"passed"`
			Failed   int `json:"failed"`
			ExitCode int `json:"exit_code"`
		} `json:"evaluate_report"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("decode %s: %w", RustPublicBaselinePath, err)
	}
	r := doc.Report
	if r.Executed != PublicCorpusSize || r.Passed != PublicCorpusSize || r.Failed != 0 || r.ExitCode != 0 {
		return fmt.Errorf("%s records executed=%d passed=%d failed=%d exit=%d; want %d/%d/0/0",
			RustPublicBaselinePath, r.Executed, r.Passed, r.Failed, r.ExitCode, PublicCorpusSize, PublicCorpusSize)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Family D: the differential regression probes. Ranks four and five only, both
// content-bound, both from their own recorded transcript. This family is the
// negative control: it is exactly the rank-four-against-rank-five comparison
// AC2 says cannot settle a question on its own, with no higher oracle present,
// so no proposition in it may be marked overridden.
// ---------------------------------------------------------------------------

func censusDiffProbe(root string) (Family, error) {
	java, err := readArm(root, JavaArmPath)
	if err != nil {
		return Family{}, err
	}
	rust, err := readArm(root, RustArmPath)
	if err != nil {
		return Family{}, err
	}
	if len(java) != DiffProbeCount || len(rust) != DiffProbeCount {
		return Family{}, fmt.Errorf("arms hold %d and %d records, want %d each", len(java), len(rust), DiffProbeCount)
	}

	f := Family{
		ID:           FamilyDiffProbe,
		Question:     "On this differential probe, what normalized observation does the endpoint produce?",
		VerdictSpace: []string{"outcome/final_state/error-code/close-code/counts tuple, canonically encoded"},
		RankSources: []RankSource{
			{
				Rank: RankJavaObservation, RankName: RankJavaObservation.String(), Strength: SourceContent,
				Paths: []string{JavaArmPath}, ArtifactGroup: "differential-java-arm",
				Note: "The recorded Java arm, one line per probe, produced by the pinned Java-WebSocket 1.6.0 oracle process.",
			},
			{
				Rank: RankRustObservation, RankName: RankRustObservation.String(), Strength: SourceContent,
				Paths: []string{RustArmPath}, ArtifactGroup: "differential-rust-arm",
				Note: "The recorded Rust arm, one line per probe, produced by the ws_core harness.",
			},
			{
				Rank: RankRFC6455, RankName: RankRFC6455.String(), Strength: SourceAbsent,
				Note: "No committed artifact states an RFC verdict per probe id, so rank one abstains here.",
			},
			{
				Rank: RankAutobahnInScope, RankName: RankAutobahnInScope.String(), Strength: SourceAbsent,
				Note: "The probes are deliberately outside the Autobahn selection, so rank two abstains here.",
			},
			{
				Rank: RankNeutralExpectation, RankName: RankNeutralExpectation.String(), Strength: SourceAbsent,
				Note: "The manifest states these probes are deliberately NOT in the neutral public corpus, so rank three abstains here.",
			},
		},
		CrossChecks: []string{
			"each probe's request_digest was asserted equal between the two arms, so the arms answered the same request",
			"the free-text `detail` field is excluded from the verdict: the two arms word the same rejection differently by construction and comparing prose would manufacture divergence",
		},
	}

	ids := make([]string, 0, len(java))
	for id := range java {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		j := java[id]
		r, ok := rust[id]
		if !ok {
			return Family{}, fmt.Errorf("probe %s: absent from %s", id, RustArmPath)
		}
		if j.RequestDigest != r.RequestDigest {
			return Family{}, fmt.Errorf("probe %s: arms answered different requests (%s vs %s)", id, j.RequestDigest, r.RequestDigest)
		}
		f.Propositions = append(f.Propositions, Proposition{
			ID:       fmt.Sprintf("%s/%s", FamilyDiffProbe, id),
			Family:   FamilyDiffProbe,
			Question: fmt.Sprintf("Differential probe %s: what normalized observation?", id),
			Opinions: []Opinion{
				{Rank: RankJavaObservation, Verdict: j.verdict(), Source: fmt.Sprintf("%s#<%s>", JavaArmPath, id)},
				{Rank: RankRustObservation, Verdict: r.verdict(), Source: fmt.Sprintf("%s#<%s>", RustArmPath, id)},
			},
		})
	}
	return f, nil
}

type armRecord struct {
	RequestID     string `json:"request_id"`
	RequestDigest string `json:"request_digest"`
	Outcome       string `json:"outcome"`
	FinalState    string `json:"final_state"`
	Error         *struct {
		Code      string `json:"code"`
		CloseCode *int   `json:"close_code"`
	} `json:"error"`
	Counts map[string]int `json:"counts"`
}

// verdict is the normalized observation. The free-text `detail` and the
// `runtime` block are excluded: the two arms word the same rejection
// differently by construction, and the runtime identity is the point of the
// comparison rather than part of it.
func (a armRecord) verdict() string {
	var b strings.Builder
	fmt.Fprintf(&b, "outcome=%s;final_state=%s", a.Outcome, a.FinalState)
	if a.Error != nil {
		fmt.Fprintf(&b, ";error_code=%s", a.Error.Code)
		if a.Error.CloseCode != nil {
			fmt.Fprintf(&b, ";close_code=%d", *a.Error.CloseCode)
		}
	}
	keys := make([]string, 0, len(a.Counts))
	for k := range a.Counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, ";%s=%d", k, a.Counts[k])
	}
	return b.String()
}

func readArm(root, path string) (map[string]armRecord, error) {
	lines, err := readJSONLines(root, path)
	if err != nil {
		return nil, err
	}
	out := make(map[string]armRecord, len(lines))
	for i, line := range lines {
		var rec armRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", path, i+1, err)
		}
		if rec.RequestID == "" {
			return nil, fmt.Errorf("%s line %d: no request_id", path, i+1)
		}
		if _, dup := out[rec.RequestID]; dup {
			return nil, fmt.Errorf("%s names %s twice", path, rec.RequestID)
		}
		out[rec.RequestID] = rec
	}
	return out, nil
}

func readJSONLines(root, rel string) ([][]byte, error) {
	file, err := os.Open(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", rel, err)
	}
	defer file.Close()

	var out [][]byte
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 1<<20), 1<<24)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		out = append(out, []byte(line))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", rel, err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s holds no records", rel)
	}
	return out, nil
}
