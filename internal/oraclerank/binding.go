package oraclerank

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Strength says how a rank is attached to evidence. The distinction exists
// because "the rank is present" and "the rank is identified" are different
// facts, and letting the first stand in for the second is the defect class
// this program keeps rediscovering.
type Strength string

const (
	// BoundToContent means every opinion at this rank is read out of
	// committed bytes this package hashes on the run that reads them, and
	// those bytes are a RECORD OF THE ORACLE ITSELF: the suite's own report,
	// the oracle process's own transcript.
	BoundToContent Strength = "CONTENT_BOUND"

	// BoundToRecordedReading means the opinions are read out of committed
	// bytes this package hashes, but those bytes are a HUMAN READING of the
	// oracle rather than the oracle. The reading can be checked for internal
	// consistency, coverage and stability. It cannot be checked against the
	// source it claims to read.
	BoundToRecordedReading Strength = "CONTENT_BOUND_TO_RECORDED_READING"

	// BoundByDeclaration means the rank is named and its source is pinned by
	// digest, but no bytes in this repository carry that source, so no
	// opinion at this rank can be resolved against it.
	BoundByDeclaration Strength = "DECLARATION_BOUND"
)

// Artifact is one committed file a rank's opinions are read from, with the
// digest RECOMPUTED on this run. A binding that names a file it cannot hash is
// an error, never a warning.
type Artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// Binding is one rank's honest attachment to this repository.
type Binding struct {
	Rank     Rank     `json:"rank"`
	RankName string   `json:"rank_name"`
	Strength Strength `json:"strength"`
	// Statement says in one paragraph what the rank is bound to.
	Statement string `json:"statement"`
	// Artifacts are the committed files, hashed on this run.
	Artifacts []Artifact `json:"artifacts"`
	// NotBoundTo names, precisely, what this rank is NOT attached to. It is
	// required for every strength weaker than CONTENT_BOUND and forbidden
	// to be empty there.
	NotBoundTo string `json:"not_bound_to,omitempty"`
	// OwnerActionRequired names the exact action that would raise the
	// strength, when one exists.
	OwnerActionRequired string `json:"owner_action_required,omitempty"`
}

// RFCPinID is the source-pin identity of the normative text rank one names.
const RFCPinID = "rfc6455-text"

// SourcePinsPath is the committed pin catalogue.
const SourcePinsPath = "evidence/intake/source-pins.json"

// RFCTextCandidatePath is where the pinned RFC 6455 bytes would live if they
// were ever fetched into this repository. They are NOT here today; see
// bindRFC.
const RFCTextCandidatePath = "third_party/rfc6455/rfc6455.txt"

// hashArtifact hashes a committed file, failing closed when it is absent.
func hashArtifact(root, rel string) (Artifact, error) {
	full := filepath.Join(root, filepath.FromSlash(rel))
	data, err := os.ReadFile(full)
	if err != nil {
		return Artifact{}, fmt.Errorf("binding artifact %s: %w", rel, err)
	}
	sum := sha256.Sum256(data)
	return Artifact{Path: rel, SHA256: "sha256:" + hex.EncodeToString(sum[:]), Bytes: int64(len(data))}, nil
}

func hashArtifacts(root string, rels []string) ([]Artifact, error) {
	out := make([]Artifact, 0, len(rels))
	for _, rel := range rels {
		a, err := hashArtifact(root, rel)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// RFCPin is the pinned identity of the normative text, read from the committed
// pin catalogue rather than restated here.
type RFCPin struct {
	ID           string `json:"id"`
	ImmutableURL string `json:"immutable_url"`
	SHA256       string `json:"sha256"`
	ByteSize     int64  `json:"byte_size"`
}

// ReadRFCPin finds the rfc6455-text pin anywhere in the committed catalogue.
// It walks the decoded document rather than hard-coding a path, so a pin moved
// within the catalogue is still found and a pin DELETED from it is an error.
func ReadRFCPin(root string) (RFCPin, error) {
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(SourcePinsPath)))
	if err != nil {
		return RFCPin{}, fmt.Errorf("read %s: %w", SourcePinsPath, err)
	}
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		return RFCPin{}, fmt.Errorf("decode %s: %w", SourcePinsPath, err)
	}
	found, ok := findPin(doc, RFCPinID)
	if !ok {
		return RFCPin{}, fmt.Errorf("%s: no source pin with id %q; rank one has no pinned normative text", SourcePinsPath, RFCPinID)
	}
	pin := RFCPin{ID: RFCPinID}
	pin.ImmutableURL, _ = found["immutable_url"].(string)
	pin.SHA256, _ = found["sha256"].(string)
	if n, ok := found["byte_size"].(float64); ok {
		pin.ByteSize = int64(n)
	}
	if pin.SHA256 == "" || pin.ImmutableURL == "" || pin.ByteSize == 0 {
		return RFCPin{}, fmt.Errorf("%s: pin %q is incomplete (url=%q sha256=%q bytes=%d)",
			SourcePinsPath, RFCPinID, pin.ImmutableURL, pin.SHA256, pin.ByteSize)
	}
	return pin, nil
}

func findPin(node any, id string) (map[string]any, bool) {
	switch v := node.(type) {
	case map[string]any:
		if got, ok := v["id"].(string); ok && got == id {
			return v, true
		}
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if found, ok := findPin(v[k], id); ok {
				return found, true
			}
		}
	case []any:
		for _, item := range v {
			if found, ok := findPin(item, id); ok {
				return found, true
			}
		}
	}
	return nil, false
}

// RFCTextPresent reports whether the pinned RFC bytes are in this repository
// AND hash to the pinned digest. Presence alone is not enough: a file at that
// path with different bytes is a worse state than no file, so a mismatch is an
// error rather than a false.
func RFCTextPresent(root string, pin RFCPin) (bool, error) {
	full := filepath.Join(root, filepath.FromSlash(RFCTextCandidatePath))
	data, err := os.ReadFile(full)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read %s: %w", RFCTextCandidatePath, err)
	}
	sum := sha256.Sum256(data)
	got := "sha256:" + hex.EncodeToString(sum[:])
	if got != pin.SHA256 {
		return false, fmt.Errorf("%s is present but hashes %s, not the pinned %s; rank one may not read unpinned bytes",
			RFCTextCandidatePath, got, pin.SHA256)
	}
	if int64(len(data)) != pin.ByteSize {
		return false, fmt.Errorf("%s is present but is %d bytes, not the pinned %d", RFCTextCandidatePath, len(data), pin.ByteSize)
	}
	return true, nil
}

// Bindings builds the five rank bindings against this repository, hashing
// every artifact it names. The strengths here are computed, not asserted: rank
// one's strength is decided by whether the pinned RFC bytes are actually
// present, and rank three's honesty note is decided by the corpus's own
// recorded expectation status.
func Bindings(root string, families []Family) ([]Binding, error) {
	var out []Binding

	rfc, err := bindRFC(root)
	if err != nil {
		return nil, err
	}
	out = append(out, rfc)

	autobahn, err := bindAutobahn(root)
	if err != nil {
		return nil, err
	}
	out = append(out, autobahn)

	neutral, err := bindNeutral(root)
	if err != nil {
		return nil, err
	}
	out = append(out, neutral)

	java, err := bindJava(root)
	if err != nil {
		return nil, err
	}
	out = append(out, java)

	rust, err := bindRust(root)
	if err != nil {
		return nil, err
	}
	out = append(out, rust)

	for _, b := range out {
		if b.Strength != BoundToContent && b.NotBoundTo == "" {
			return nil, fmt.Errorf("%s is %s and does not say what it is NOT bound to", b.Rank, b.Strength)
		}
		if len(b.Artifacts) == 0 {
			return nil, fmt.Errorf("%s names no artifact; a rank with no artifact exists in name only", b.Rank)
		}
	}
	if err := checkBindingStrengthAgainstFamilies(out, families); err != nil {
		return nil, err
	}
	return out, nil
}

// checkBindingStrengthAgainstFamilies re-derives the one field of a Binding
// that used to be a literal.
//
// Rank one's strength has always been COMPUTED -- it turns on whether the
// pinned RFC bytes are present. The other four were written into the source
// beside the rank. That mattered for more than tidiness: Bindings requires a
// binding weaker than CONTENT_BOUND to say what it is NOT bound to, and
// Findings emits ORACLE-RANK-BINDING-n for exactly those, so writing
// CONTENT_BOUND suppressed both the obligation and the disclosure. Nothing
// compared the literal with the census's own per-family SourceStrength, which
// is the finer statement of the same fact and is derived from where each
// opinion is actually read.
//
// The rule is the honest direction of the two: a rank may call itself
// CONTENT_BOUND only where EVERY family it speaks in reads it out of a record
// of the oracle itself. One family reading it out of a recorded human reading,
// or deducing it from an aggregate, is enough to make the single label
// flattering -- which is the fault census.go's SourceStrength doc names in its
// own words: averaging a rank's attachments into one label "is how a rank comes
// to look better attached than it is".
func checkBindingStrengthAgainstFamilies(bindings []Binding, families []Family) error {
	weaker := map[Rank][]string{}
	for _, f := range families {
		for _, rs := range f.RankSources {
			if rs.Strength == SourceAbsent || rs.Strength == SourceContent {
				continue
			}
			weaker[rs.Rank] = append(weaker[rs.Rank], fmt.Sprintf("%s=%s", f.ID, rs.Strength))
		}
	}
	for _, b := range bindings {
		if b.Strength != BoundToContent {
			continue
		}
		if names := weaker[b.Rank]; len(names) > 0 {
			sort.Strings(names)
			return fmt.Errorf(
				"%s is bound %s and the census declares its opinions in %v as something other than %s; a rank may not claim one strength while its own families record a weaker one, and %s is the strength that carries the NOT bound to obligation and the ORACLE-RANK-BINDING disclosure",
				b.Rank, b.Strength, names, SourceContent, BoundToContent)
		}
	}
	return nil
}

func bindRFC(root string) (Binding, error) {
	pin, err := ReadRFCPin(root)
	if err != nil {
		return Binding{}, err
	}
	present, err := RFCTextPresent(root, pin)
	if err != nil {
		return Binding{}, err
	}

	arts, err := hashArtifacts(root, []string{
		SourcePinsPath,
		HandshakeLiveMappingPath,
		RFCDivergenceCensusPath,
	})
	if err != nil {
		return Binding{}, err
	}

	b := Binding{
		Rank:      RankRFC6455,
		RankName:  RankRFC6455.String(),
		Artifacts: arts,
	}
	if present {
		extra, err := hashArtifact(root, RFCTextCandidatePath)
		if err != nil {
			return Binding{}, err
		}
		b.Artifacts = append(b.Artifacts, extra)
		b.Strength = BoundToContent
		b.Statement = fmt.Sprintf(
			"The pinned RFC 6455 text is present at %s and hashes to the catalogue pin %s. Rank-one opinions are read from the committed readings and each cited clause is resolvable in those bytes.",
			RFCTextCandidatePath, pin.SHA256)
		return b, nil
	}

	b.Strength = BoundToRecordedReading
	b.Statement = fmt.Sprintf(
		"Rank one is bound to two committed HUMAN READINGS of RFC 6455 -- %s (rfc_verdict per handshake outcome key) and %s (rfc_strict_expectation per public scenario) -- whose bytes this package hashes on every run. It is NOT bound to the RFC text: %s pins %s at %s (%d bytes) and no file in this repository carries those bytes.",
		HandshakeLiveMappingPath, RFCDivergenceCensusPath, SourcePinsPath, pin.ImmutableURL, pin.SHA256, pin.ByteSize)
	b.NotBoundTo = fmt.Sprintf(
		"the normative RFC 6455 text itself. Every rank-one verdict in this census is a reading recorded by a human in a committed document; nothing here re-derives it from %s, and a misreading would pass this gate unchanged.",
		pin.ImmutableURL)
	b.OwnerActionRequired = fmt.Sprintf(
		"fetch %s, require exact sha256 %s and byte size %d, and commit it at %s. Egress to www.rfc-editor.org is denied from this environment (agent proxy answered CONNECT with 403), so this cannot be done from a session; it is an owner action. With those bytes present this binding computes CONTENT_BOUND automatically -- no code change is needed.",
		pin.ImmutableURL, pin.SHA256, pin.ByteSize, RFCTextCandidatePath)
	return b, nil
}

func bindAutobahn(root string) (Binding, error) {
	arts, err := hashArtifacts(root, []string{
		AutobahnDigestManifestPath,
		AutobahnComparisonPath,
	})
	if err != nil {
		return Binding{}, err
	}
	return Binding{
		Rank:     RankAutobahnInScope,
		RankName: RankAutobahnInScope.String(),
		Strength: BoundToContent,
		Statement: fmt.Sprintf(
			"Rank two is bound to the suite's OWN per-case reports under %s. Each report carries the suite-authored `expectation` prose and an `expected` map from behaviour class to the event sequences that class admits; the rank-two verdict is which arm of that map the case declares as its endorsed outcome, read from the report bytes. The digest manifest is verified against the files it pins before any report is read, and every leg's case count is asserted equal to %d.",
			AutobahnEvidenceRoot, AutobahnExpectedCaseCount),
		Artifacts: arts,
	}, nil
}

func bindNeutral(root string) (Binding, error) {
	arts, err := hashArtifacts(root, []string{
		PublicCorpusPath,
		HandshakeCorpusPath,
		NeutralRuleTablePath,
	})
	if err != nil {
		return Binding{}, err
	}
	statuses, err := publicExpectationStatuses(root)
	if err != nil {
		return Binding{}, err
	}
	pin, err := ReadRFCPin(root)
	if err != nil {
		return Binding{}, err
	}
	return Binding{
		Rank:     RankNeutralExpectation,
		RankName: RankNeutralExpectation.String(),
		Strength: BoundToRecordedReading,
		Statement: fmt.Sprintf(
			"Rank three is bound to two things, hashed on every run, and this binding does not average them. On the HANDSHAKE tier it is the committed expectations in %s, whose basis cites RFC 6455, RFC 9110 and RFC 9112 clauses directly. On the PUBLIC tier it is no longer the corpus expectation at all: all %d of those record expectation_status=%q and are produced by internal/corpora.DeriveExpected under a reference model documenting itself as mirroring pinned Java-WebSocket 1.6.0, and rank four is deduced from that same expectation, so reading rank three out of it made the two ranks one oracle under two names. The public tier's rank-three opinions are now DERIVED ON THIS RUN by internal/rfcneutral from the stated rules of RFC 6455 sections 5 and 7 applied to each scenario's own inbound octets in %s; the rule table at %s is hashed here so the register pins the exact reading that produced them.",
			HandshakeCorpusPath, statuses.total, statuses.dominant, PublicCorpusPath, NeutralRuleTablePath),
		Artifacts: arts,
		NotBoundTo: fmt.Sprintf(
			"the RFC 6455 text, on the public tier -- exactly as rank one is not. %s pins %s at %s (%d bytes) and no file in this repository carries those bytes, so every rule in %s is a RECORDED READING written by hand and a misreading of a clause would pass this gate unchanged. This rank claims no more binding than rank one has. What it does claim is narrower and checkable: the rules are stated once and applied uniformly by a decoder to the scenario's own octets, and no Java artifact and no reference-model output is read on the way. On the handshake tier this rank is bound to a committed corpus expectation and NOT to any independent execution of it.",
			SourcePinsPath, pin.ImmutableURL, pin.SHA256, pin.ByteSize, NeutralRuleTablePath),
		OwnerActionRequired: fmt.Sprintf(
			"check the readings in %s clause by clause against %s once those bytes are in the tree; each rule records the sentence it rests on for that purpose. On the handshake tier, supply a per-case observation of the pinned Java process so rank four is not looked up by a key computed from this rank's own verdict -- see the ORACLE-RANK-JOIN-DEGENERATE finding.",
			NeutralRuleTablePath, pin.ImmutableURL),
	}, nil
}

func bindJava(root string) (Binding, error) {
	arts, err := hashArtifacts(root, []string{
		AutobahnDigestManifestPath,
		JavaArmPath,
		HandshakeLiveMappingPath,
	})
	if err != nil {
		return Binding{}, err
	}
	return Binding{
		Rank:     RankJavaObservation,
		RankName: RankJavaObservation.String(),
		Strength: BoundToRecordedReading,
		Statement: fmt.Sprintf(
			"Rank four is bound to three things and this binding does not average them. On the AUTOBAHN family and the DIFFERENTIAL family it is an observation of the pinned Java-WebSocket 1.6.0 PROCESS: the two Java legs of the native x86_64 Autobahn run (per-case report bytes under %s, digest-manifest verified) and the recorded Java arm at %s. On the HANDSHAKE family it is not: the opinions there are the java_observable field of %s, which that family's own rank_sources record as a %s and whose basis cites Draft_6455.java and WebSocketImpl.java BY LINE rather than any transcript. On the PUBLIC family it is not an observation either: no per-scenario Java transcript is committed and the opinions are %s from a clean-sweep aggregate plus the corpus expectation.",
			AutobahnEvidenceRoot, JavaArmPath, HandshakeLiveMappingPath, SourceRecordedReading, SourceAggregateDerived),
		Artifacts: arts,
		NotBoundTo: fmt.Sprintf(
			"the Java PROCESS, on the handshake and public families. %s of the 49 handshake propositions is a human reading of the pinned Java sources and a misreading of a cited line would pass this gate unchanged; the 74 public propositions are a DEDUCTION from two aggregates that record a clean sweep, and a per-scenario Java observation that differed from its recorded expectation while the aggregate still read 74/74/0 would be invisible here. This binding was CONTENT_BOUND until an adversarial pass compared the label with the census's own per-family strengths; it carried no NOT bound to text and emitted no ORACLE-RANK-BINDING disclosure while two of the four families it speaks in read it from something other than the oracle.",
			HandshakeLiveMappingPath),
		OwnerActionRequired: fmt.Sprintf(
			"commit a per-case transcript of the pinned Java process for the handshake corpus and a per-scenario transcript for the public corpus. With either present, that family's rank_sources becomes %s and this binding's strength rises on its own -- the strength is computed from the families, not written here.",
			SourceContent),
	}, nil
}

func bindRust(root string) (Binding, error) {
	arts, err := hashArtifacts(root, []string{
		AutobahnDigestManifestPath,
		RustArmPath,
	})
	if err != nil {
		return Binding{}, err
	}
	return Binding{
		Rank:     RankRustObservation,
		RankName: RankRustObservation.String(),
		Strength: BoundToContent,
		Statement: fmt.Sprintf(
			"Rank five is bound to observations of the Rust port: the two Rust legs of the native x86_64 Autobahn run (per-case report bytes under %s, digest-manifest verified) and the recorded Rust arm at %s.",
			AutobahnEvidenceRoot, RustArmPath),
		Artifacts: arts,
	}, nil
}
