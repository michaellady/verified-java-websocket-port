package normcollide

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// DocumentSchemaVersion is the version of the emitted evidence document.
const DocumentSchemaVersion = "1.0.0"

// DocumentEntityType names the artifact in the evidence tree.
const DocumentEntityType = "NormalizationCollisionAudit"

// DocumentPath is the committed document, relative to the repository root.
const DocumentPath = "evidence/normalization-collisions/audit.json"

// Document is the committed audit artifact. Every count in it is recomputed
// from real process output; the prose (Erases, Mechanism, Disclosure, Why) is
// authored, and the verdicts those sentences describe are not.
type Document struct {
	SchemaVersion string `json:"schema_version"`
	EntityType    string `json:"entity_type"`
	Note          string `json:"note"`

	RecomputedFrom Provenance   `json:"recomputed_from"`
	Surface        []Projection `json:"normalization_surface"`
	Probes         []ProbeDoc   `json:"probes"`
	Candidates     []Candidate  `json:"undecided_candidates"`
	Census         []Census     `json:"scored_corpus_census"`
	Bounds         Bounds       `json:"headline_bounds"`
	ScopeLimits    []string     `json:"scope_limits"`
}

// Provenance records what actually ran.
type Provenance struct {
	// Harness is the binary that answered every probe, with its digest.
	Harness string `json:"harness"`
	// Comparator names the function that decided every verdict.
	Comparator string `json:"comparator"`
	// IdentityFieldsStripped is the exact list removed before comparison.
	IdentityFieldsStripped []string `json:"identity_fields_stripped"`
	// ProbeCount, ConfirmedCount and RefutedCount are recounted, not typed.
	ProbeCount     int `json:"probe_count"`
	ConfirmedCount int `json:"confirmed_count"`
	RefutedCount   int `json:"refuted_count"`
	CandidateCount int `json:"undecided_candidate_count"`
}

// ProbeDoc is one probe and its measured result.
type ProbeDoc struct {
	Probe
	// RequestLines are the exact JSONL lines that were fed to the harness,
	// so the run is reproducible from the document alone.
	RequestLines []string `json:"request_lines"`
	// Result is what the run reported.
	Result Result `json:"result"`
}

// Bounds states what the confirmed collisions mean for the headline numbers.
// The numbers here are recomputed from the census; the sentences read them.
type Bounds struct {
	// PublicTotal and PublicBlindRows describe the 74/74.
	PublicTotal     int `json:"public_corpus_rows"`
	PublicBlindRows int `json:"public_rows_whose_projection_erases_every_observation_stream"`
	// PublicDistinct is how many DISTINCT scored observations the 74 rows
	// carry, and PublicShared how many rows share one with another row.
	PublicDistinct  int    `json:"public_distinct_scored_observations"`
	PublicShared    int    `json:"public_rows_sharing_an_observation"`
	PublicStatement string `json:"public_statement"`
	// HandshakeTotal, HandshakeDistinct and HandshakeShared describe the 49/49.
	HandshakeTotal     int    `json:"handshake_corpus_cases"`
	HandshakeDistinct  int    `json:"handshake_distinct_scored_observations"`
	HandshakeShared    int    `json:"handshake_cases_sharing_an_observation"`
	HandshakeLargest   int    `json:"handshake_largest_equivalence_class"`
	HandshakeStatement string `json:"handshake_statement"`
	// ClaimVocabulary states what kind of claim this document supports.
	ClaimVocabulary string `json:"claim_vocabulary"`
}

// Build runs every probe and every census and assembles the document.
func Build(root string, runner Runner) (*Document, error) {
	document := &Document{
		SchemaVersion: DocumentSchemaVersion,
		EntityType:    DocumentEntityType,
		Note: "Normalization-collision census. A collision is two genuinely different wire " +
			"behaviours mapping onto one normalized observation. Every probe below was DECIDED " +
			"BY RUNNING the real harness on two seed requests and applying the real differential " +
			"comparator to the two answers; no verdict is predicted. Confirmed collisions are " +
			"separated from undecided candidates, and a candidate is never counted as a finding.",
		Surface:    Projections(),
		Candidates: Candidates(),
		RecomputedFrom: Provenance{
			Harness:                runner.Identity(),
			Comparator:             "internal/diffregress.CompareResponses (the comparator the headline number uses)",
			IdentityFieldsStripped: IdentityFields(),
		},
	}

	for _, probe := range Probes() {
		result, err := Decide(runner, probe)
		if err != nil {
			return nil, err
		}
		lines := make([]string, 0, 4)
		seeds := []Seed{probe.CollisionA, probe.CollisionB}
		if probe.WitnessA != nil && probe.WitnessB != nil {
			seeds = append(seeds, *probe.WitnessA, *probe.WitnessB)
		}
		for _, seed := range seeds {
			line, err := seed.Line()
			if err != nil {
				return nil, err
			}
			lines = append(lines, line)
		}
		document.Probes = append(document.Probes, ProbeDoc{Probe: probe, RequestLines: lines, Result: result})
		document.RecomputedFrom.ProbeCount++
		switch result.Verdict {
		case Confirmed:
			document.RecomputedFrom.ConfirmedCount++
		case Refuted:
			document.RecomputedFrom.RefutedCount++
		}
	}
	document.RecomputedFrom.CandidateCount = len(document.Candidates)

	public, err := MeasureTranscript(filepath.Join(root, PublicArmPath), ClassifyBehaviourKeys)
	if err != nil {
		return nil, err
	}
	public.Source = PublicArmPath
	handshake, err := MeasureHandshake(root, runner)
	if err != nil {
		return nil, err
	}
	document.Census = []Census{public, handshake}

	if err := PartitionCensus(document.Census); err != nil {
		return nil, err
	}

	var blind int
	for _, keySet := range public.KeySets {
		if keySet.Projection == "behaviour.failure" || keySet.Projection == "behaviour.output_limit" {
			blind += keySet.Rows
		}
	}
	document.Bounds = Bounds{
		PublicTotal:     public.Rows,
		PublicBlindRows: blind,
		PublicDistinct:  public.DistinctScoredRows,
		PublicShared:    public.RowsSharingAnObservation,
		PublicStatement: fmt.Sprintf(
			"%d of the %d public rows are error rows. NC-01 and NC-04 are CONFIRMED on that "+
				"projection, so for those %d rows the differential compares error.code, "+
				"error.close_code, final_state and the seven counters — and NOTHING about what the "+
				"connection did. events[], frames[], transitions[] and close are absent from the "+
				"row entirely, and error.detail is classified non-semantic. So %d/%d means: %d "+
				"requests were answered, %d of them scored on the full observation surface and %d "+
				"scored on ten scalars. It does not mean %d behaviours were compared. "+
				"MEASURED, not inferred: the %d rows carry only %d DISTINCT scored observations, "+
				"because %d of them (us005.pub.0039 and us005.pub.0066, probe NC-04) are "+
				"byte-identical once identity is removed — two different frames, differing in the "+
				"FIN bit and in every payload octet, that the corpus cannot tell apart. The "+
				"headline's ceiling is therefore %d distinguishable answers, not %d.",
			blind, public.Rows, blind, public.Rows, public.Rows, public.Rows,
			public.Rows-blind, blind, public.Rows, public.Rows,
			public.DistinctScoredRows, public.RowsSharingAnObservation,
			public.DistinctScoredRows, public.Rows),
		HandshakeTotal:    handshake.Rows,
		HandshakeDistinct: handshake.DistinctScoredRows,
		HandshakeShared:   handshake.RowsSharingAnObservation,
		HandshakeLargest:  handshake.LargestClass,
		HandshakeStatement: fmt.Sprintf(
			"The %d handshake cases produce only %d DISTINCT scored observations. %d of the %d "+
				"cases share their observation with at least one other case, and the largest "+
				"equivalence class holds %d cases. 49/49 therefore certifies at most %d "+
				"distinguishable answers, not 49. NC-07, NC-08 and NC-09 are the confirmed "+
				"mechanisms: the HTTP head is discarded, `incomplete` carries no content, and "+
				"a rejection reports only a two-valued channel plus a constant close code.",
			handshake.Rows, handshake.DistinctScoredRows, handshake.RowsSharingAnObservation,
			handshake.Rows, handshake.LargestClass, handshake.DistinctScoredRows),
		ClaimVocabulary: "BOUNDED. Each confirmed collision is an OBSERVED fact about the shipped " +
			"projection, established by running it. The ENUMERATION of the surface is not proved " +
			"complete: it reads five named sites, and a distinction none of them mentions cannot " +
			"be found by reading them. DIV-02 is exactly that case and is in this document only " +
			"because a person had already found it out of band.",
	}
	document.ScopeLimits = []string{
		"This audit ran ONE arm. Every probe was answered by the Rust harness; the pinned Java " +
			"oracle was NOT executed. That is sound for the claim being made — a collision is a " +
			"property of the PROJECTION, and both arms share the projection by construction — but " +
			"it means nothing here is a Java-versus-Rust fidelity result.",
		"No AWS, benchmark or Autobahn run was performed.",
		"The surface enumeration covers the two oracle protocols only. Anything the protocols " +
			"never carry — sockets, timing, memory, scheduling — is outside it by construction, " +
			"which is exactly how DIV-02 hid.",
		"NC-02's projection (behaviour.output_limit) is CONFIRMED but DORMANT: no row of the " +
			"current 74 reaches it, because every public scenario carries the full 4194304-byte " +
			"budget. It bounds what a future corpus could hide, not today's number.",
		"The handshake census measures OUR arm's answers to the 49 committed cases. It is a " +
			"measurement of how coarse the observation is, not of who produced it.",
	}
	return document, nil
}

// PartitionCensus requires every observed response shape to belong to a named
// projection. A shape this audit never enumerated arrives with an empty
// projection name and fails here, which is the point: the surface table cannot
// go stale silently while the document keeps claiming to describe it.
//
// This is exported so it can be attacked directly. Build calls it, but Build
// needs a harness, so a check that lived only inside Build would have no test
// in the default suite — and a deletion attack confirmed exactly that before
// it was lifted out.
func PartitionCensus(censuses []Census) error {
	for _, census := range censuses {
		for _, keySet := range census.KeySets {
			if keySet.Projection == "" {
				return fmt.Errorf("%s carries an unclassified response shape %v: "+
					"the normalization surface table is incomplete", census.Source, keySet.Keys)
			}
		}
	}
	return nil
}

// Marshal renders the document deterministically.
func Marshal(document *Document) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// Recompute runs the whole audit and renders the document bytes.
func Recompute(root string, runner Runner) ([]byte, *Document, error) {
	document, err := Build(root, runner)
	if err != nil {
		return nil, nil, err
	}
	encoded, err := Marshal(document)
	if err != nil {
		return nil, nil, err
	}
	return encoded, document, nil
}

// Verify recomputes the document and compares it byte for byte with the
// committed one. The committed document is never read as an input to the
// recomputation, so this cannot pass by copying it.
func Verify(root string, runner Runner) error {
	recomputed, _, err := Recompute(root, runner)
	if err != nil {
		return err
	}
	path := filepath.Join(root, DocumentPath)
	committed, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("committed audit document: %w", err)
	}
	if bytes.Equal(recomputed, committed) {
		return nil
	}
	return fmt.Errorf("%s disagrees with the run it claims to describe: %s",
		DocumentPath, firstDifference(committed, recomputed))
}

// Write emits the recomputed document to its committed path.
func Write(root string, runner Runner) ([]byte, error) {
	recomputed, _, err := Recompute(root, runner)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(root, DocumentPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, recomputed, 0o644); err != nil {
		return nil, err
	}
	return recomputed, nil
}

func firstDifference(committed, recomputed []byte) string {
	committedLines := bytes.Split(committed, []byte("\n"))
	recomputedLines := bytes.Split(recomputed, []byte("\n"))
	for i := 0; i < len(committedLines) && i < len(recomputedLines); i++ {
		if !bytes.Equal(committedLines[i], recomputedLines[i]) {
			return fmt.Sprintf("line %d: committed %q, recomputed %q",
				i+1, clip(committedLines[i]), clip(recomputedLines[i]))
		}
	}
	return fmt.Sprintf("committed has %d lines, recomputed has %d",
		len(committedLines), len(recomputedLines))
}

func clip(line []byte) string {
	if len(line) > 160 {
		return string(line[:160]) + "..."
	}
	return string(line)
}

// FileDigest is the SHA-256 of a file, used to record which binary answered.
func FileDigest(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func decodeBase64(value string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(value)
}

// SortedProbeIDs lists the catalog's probe IDs, for report rendering.
func SortedProbeIDs() []string {
	var ids []string
	for _, probe := range Probes() {
		ids = append(ids, probe.ID)
	}
	sort.Strings(ids)
	return ids
}
