// Package projection derives the owner-relaxed US-027 acceptance ledger and
// its deliberately limited local public projection.
package projection

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

const (
	MechanicsPass         = "PASS_OWNER_RELAXED_PUBLIC_PROJECTION_MECHANICS"
	AcceptanceBlocked     = "INDEPENDENT_ACCEPTANCE_BLOCKED"
	Assurance             = "OWNER_ATTESTED_NOT_INDEPENDENT"
	CheckoutNotVerified   = "NOT_VERIFIED"
	DeclaredSubjectCommit = "98ddff676fe336e22ca9ae4ee7b6f8c6c9025ddc"
	DeclaredSubjectTree   = "36ee700401268621aae58639185dcdc11e4c00c6"
	CandidateRoot         = "sha256:dd96c5fb0346f736e6ddadf7848d34ceb5e4c2beefe77c1730bec6649516190e"
	ContractSHA256        = "sha256:08c14048d92b1066ad5f459d3e41e69d6e7a7cb81e8524c9c1cf06382c59f195"
)

const (
	publicBadge        = "OWNER_RELAXED_MECHANICS_COMPLETE_INDEPENDENCE_BLOCKED"
	publicFreshness    = "DECLARED_SUBJECT_CHECKOUT_NOT_VERIFIED"
	publicJavaFallback = "RETAINED_SOURCE_NOT_EXECUTABLE_DRILLED"
	publicSupersession = "UNKNOWN_NOT_AUTHORITY_BOUND"
	publicRevocation   = "UNKNOWN_NOT_AUTHORITY_BOUND"
	publicPublication  = "LOCAL_FILES_ONLY_NOT_PUBLISHED"
)

// Summary is the stable CLI result. Exit zero means these bounded mechanics
// completed; AcceptanceState intentionally remains blocked.
type Summary struct {
	MechanicsStatus      string `json:"mechanics_status"`
	AcceptanceState      string `json:"acceptance_state"`
	ChildStoryCount      int    `json:"child_story_count"`
	ChildMechanicsPassed int    `json:"child_mechanics_passed"`
	StrongChildAccepted  int    `json:"strong_child_accepted"`
	FormalObligations    int    `json:"formal_obligations"`
	FormalStrongAccepted int    `json:"formal_strong_accepted"`
	FormalBlocked        int    `json:"formal_blocked"`
	SubjectCheckout      string `json:"subject_checkout"`
}

type declaredSubjectIdentity struct {
	Commit string `json:"commit"`
	Tree   string `json:"tree"`
}

type inputBinding struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

type receipt struct {
	Schema                      string                  `json:"$schema"`
	SchemaVersion               string                  `json:"schema_version"`
	ReceiptID                   string                  `json:"receipt_id"`
	Role                        string                  `json:"role"`
	Status                      string                  `json:"status"`
	Provider                    *string                 `json:"provider"`
	Model                       *string                 `json:"model"`
	ReasoningEffort             *string                 `json:"reasoning_effort"`
	DeclaredSubject             declaredSubjectIdentity `json:"declared_subject"`
	SubjectCheckoutVerification string                  `json:"subject_checkout_verification"`
	CandidateRoot               string                  `json:"candidate_root"`
	ProjectionContractSHA256    string                  `json:"projection_contract_sha256"`
	InputRootSHA256             string                  `json:"input_root_sha256"`
	MechanicsStatus             string                  `json:"mechanics_status"`
	AcceptanceState             string                  `json:"acceptance_state"`
	Independent                 bool                    `json:"independent"`
	Accepted                    bool                    `json:"accepted"`
	ProtectedAccess             bool                    `json:"protected_access"`
	Assurance                   string                  `json:"assurance"`
}

type childMechanic struct {
	StoryID string `json:"story_id"`
	State   string `json:"state"`
}

type formalObligation struct {
	ObligationID string `json:"obligation_id"`
	State        string `json:"state"`
}

type artifactDigest struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

type replayDocument struct {
	Schema                   string                  `json:"$schema"`
	SchemaVersion            string                  `json:"schema_version"`
	StoryID                  string                  `json:"story_id"`
	DeclaredSubject          declaredSubjectIdentity `json:"declared_subject"`
	SubjectCheckout          string                  `json:"subject_checkout"`
	CandidateRoot            string                  `json:"candidate_root"`
	ProjectionContractSHA256 string                  `json:"projection_contract_sha256"`
	Inputs                   []inputBinding          `json:"inputs"`
	InputRootSHA256          string                  `json:"input_root_sha256"`
	MechanicsStatus          string                  `json:"mechanics_status"`
	AcceptanceState          string                  `json:"acceptance_state"`
	ChildStoryCount          int                     `json:"child_story_count"`
	ChildMechanicsPassed     int                     `json:"child_mechanics_passed"`
	StrongChildAccepted      int                     `json:"strong_child_accepted"`
	Children                 []childMechanic         `json:"children"`
	FormalObligations        int                     `json:"formal_obligations"`
	FormalStrongAccepted     int                     `json:"formal_strong_accepted"`
	FormalBlocked            int                     `json:"formal_blocked"`
	Obligations              []formalObligation      `json:"obligations"`
	ProtectedReplay          string                  `json:"protected_replay"`
	HumanReview              string                  `json:"human_review"`
	IndependentCustodian     string                  `json:"independent_custodian"`
	PublicProjectionRoot     string                  `json:"public_projection_root"`
	Artifacts                []artifactDigest        `json:"artifacts"`
	Blockers                 []string                `json:"blockers"`
	Nonclaims                []string                `json:"nonclaims"`
	Assurance                string                  `json:"assurance"`
	IndependentReviewClaimed bool                    `json:"independent_review_claimed"`
}

type publicSnapshot struct {
	Schema               string                  `json:"$schema"`
	SchemaVersion        string                  `json:"schema_version"`
	StoryID              string                  `json:"story_id"`
	DeclaredSubject      declaredSubjectIdentity `json:"declared_subject"`
	SubjectCheckout      string                  `json:"subject_checkout"`
	ProjectionRoot       string                  `json:"projection_root"`
	Badge                string                  `json:"badge"`
	MechanicsStatus      string                  `json:"mechanics_status"`
	AcceptanceState      string                  `json:"acceptance_state"`
	ChildStoryCount      int                     `json:"child_story_count"`
	ChildMechanicsPassed int                     `json:"child_mechanics_passed"`
	StrongChildAccepted  int                     `json:"strong_child_accepted"`
	FormalObligations    int                     `json:"formal_obligations"`
	FormalBlocked        int                     `json:"formal_blocked"`
	FormalStrongAccepted int                     `json:"formal_strong_accepted"`
	Blockers             []string                `json:"blockers"`
	Freshness            string                  `json:"freshness"`
	JavaFallback         string                  `json:"java_fallback"`
	Supersession         string                  `json:"supersession"`
	Revocation           string                  `json:"revocation"`
	Publication          string                  `json:"publication"`
	ReplayCommand        string                  `json:"replay_command"`
}

type namedArtifact struct {
	path  string
	bytes []byte
}

type artifactSet struct {
	artifacts []namedArtifact
	summary   Summary
}

var canonicalInputs = []inputBinding{
	{Path: "docs/us027-independent-projection-contract.md", SHA256: ContractSHA256, Bytes: 12794},
	{Path: "contracts/laboratory-template.json", SHA256: "sha256:eb8afd7c9089456c08515b3b43182a57545ef50f40b1953944f85acdae308599", Bytes: 1000},
	{Path: "assurance/candidate-manifest.json", SHA256: "sha256:ab24fb6cbc3b811ef1d08c46c3c1b4925b03595836f5ccd65f0858fea66c9925", Bytes: 227339},
	{Path: "assurance/candidate-claims.json", SHA256: "sha256:34803e3d1a4047f86f5e59f7097481d76aa3decf88972fb557323cb7c2906024", Bytes: 23365},
	{Path: "assurance/formal/obligation-catalog.json", SHA256: "sha256:21112518f48443b4e20ecae537bed72b8c9e19167ad00bc6f325bff9374cdf59", Bytes: 76935},
	{Path: "assurance/reviews/human.json", SHA256: "sha256:aa1fa303fb264a3431087f7d6fdf0390dd6c54775ca6bd99c609886da992f2c9", Bytes: 857},
	{Path: "assurance/reviews/codex.json", SHA256: "sha256:2836daa8a54bf4019726697c820ffaf27b58aef603874c319c2042f45ad7c292", Bytes: 3467},
	{Path: "assurance/reviews/reality.json", SHA256: "sha256:e3b74a2d4cbb0a2e535e52ae41be047f6343e39834af975d09c358e38612b02f", Bytes: 976},
	{Path: "evidence/cutover.json", SHA256: "sha256:89a6eed774d4f7fd6146d6e5d04390e282e9f792f3bf0bff192e8eec31f79af1", Bytes: 2688},
	{Path: "security/release-firewall.json", SHA256: "sha256:74252e3448f76d47a978df882bc6b791b5fd0f5a21b26ac4c196e6c27caa044d", Bytes: 2847},
}

var expectedObligationIDs = []string{
	"obligation.checked-header-arithmetic",
	"obligation.control-fin-and-length",
	"obligation.length-canonical-16",
	"obligation.length-canonical-64-high-bit-zero",
	"obligation.length-canonical-7",
	"obligation.mask-equation",
	"obligation.mask-involution",
	"obligation.preallocation-cap",
	"obligation.role-masking",
	"surface.adapter.byte-stream",
	"surface.close.status-code",
	"surface.close.terminal-state",
	"surface.concurrency.command-order",
	"surface.control.ping-pong",
	"surface.errors.protocol-fault",
	"surface.fragmentation.continuation",
	"surface.framing.frame-octets",
	"surface.framing.masking",
	"surface.handshake.client-request",
	"surface.handshake.server-response",
	"surface.limits.allocation",
	"surface.messages.binary",
	"surface.messages.text-utf8",
	"surface.websocket-open",
}

var blockers = []string{
	"SUBJECT_CHECKOUT_NOT_VERIFIED",
	"CANONICAL_PRD_NOT_REPOSITORY_BOUND",
	"INDEPENDENT_CUSTODIAN_NOT_BOUND",
	"HUMAN_REVIEW_NOT_EXECUTED",
	"PROTECTED_EVALUATOR_ACCESS_NOT_EXECUTED",
	"PROVENANCE_DISTINCT_REPLAY_NOT_EXECUTED",
	"ORIGINAL_PARITY_GATES_REMAIN_BLOCKED",
	"STRONG_CHILD_GATE_CLOSURE_NOT_ESTABLISHED",
	"MEASURED_RESOURCE_ENVELOPE_NOT_ACCEPTED",
	"LIVE_CUTOVER_NOT_ACCEPTED",
	"SIGNED_ATTESTATION_NOT_AUTHORIZED",
	"EXTERNAL_PUBLICATION_NOT_AUTHORIZED",
	"PRODUCTION_DEPLOYMENT_NOT_AUTHORIZED",
	"JAVA_REMOVAL_NOT_AUTHORIZED",
}

var nonclaims = []string{
	"no verification that the supplied checkout equals the declared subject",
	"no provenance-distinct custodian, identity, or independent review",
	"no human review or protected evaluator replay",
	"no strong acceptance of all child gates or formal obligations",
	"no measured performance or live cutover acceptance",
	"no ACCEPTED, PUBLISHED, signed, or externally published result",
	"no production deployment or Java removal",
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func canonicalJSON(value any) ([]byte, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func strictDecode(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("trailing JSON content")
	}
	return nil
}

func children() []childMechanic {
	result := make([]childMechanic, 26)
	for i := range result {
		result[i] = childMechanic{StoryID: fmt.Sprintf("US-%03d", i+1), State: "PASS_OWNER_RELAXED_CHILD_MECHANICS"}
	}
	return result
}

func obligationProjection(ids []string) []formalObligation {
	result := make([]formalObligation, len(ids))
	for i, id := range ids {
		result[i] = formalObligation{ObligationID: id, State: "BLOCKED"}
	}
	return result
}

func inputRoot(bindings []inputBinding) (string, error) {
	raw, err := canonicalJSON(bindings)
	if err != nil {
		return "", err
	}
	return digest(raw), nil
}

func inputRaw(inputs map[string][]byte, name string) ([]byte, error) {
	raw, ok := inputs[name]
	if !ok {
		return nil, fmt.Errorf("input %s is absent", name)
	}
	return raw, nil
}

func validateInputs(inputs map[string][]byte) ([]string, error) {
	contractRaw, err := inputRaw(inputs, "docs/us027-independent-projection-contract.md")
	if err != nil {
		return nil, err
	}
	if digest(contractRaw) != ContractSHA256 {
		return nil, fmt.Errorf("held projection contract digest does not match emitted binding")
	}

	manifestRaw, err := inputRaw(inputs, "assurance/candidate-manifest.json")
	if err != nil {
		return nil, err
	}
	var manifest struct {
		StoryID                  string `json:"story_id"`
		CandidateRoot            string `json:"candidate_root"`
		Assurance                string `json:"assurance"`
		IndependentReviewClaimed bool   `json:"independent_review_claimed"`
	}
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil || manifest.StoryID != "US-023" || manifest.CandidateRoot != CandidateRoot || manifest.Assurance != Assurance || manifest.IndependentReviewClaimed {
		return nil, fmt.Errorf("candidate manifest ceiling or root drift")
	}

	claimsRaw, err := inputRaw(inputs, "assurance/candidate-claims.json")
	if err != nil {
		return nil, err
	}
	var claims struct {
		StoryID                  string `json:"story_id"`
		Assurance                string `json:"assurance"`
		IndependentReviewClaimed bool   `json:"independent_review_claimed"`
		Gates                    []struct {
			GateID        string `json:"gate_id"`
			ObservedState string `json:"observed_state"`
		} `json:"gates"`
	}
	if err := json.Unmarshal(claimsRaw, &claims); err != nil || claims.StoryID != "US-023" || claims.Assurance != Assurance || claims.IndependentReviewClaimed || len(claims.Gates) != 44 {
		return nil, fmt.Errorf("candidate claim denominator drift")
	}
	seenGates := map[string]bool{}
	for _, gate := range claims.Gates {
		if gate.GateID == "" || gate.ObservedState != "BLOCKED" || seenGates[gate.GateID] {
			return nil, fmt.Errorf("candidate gate ledger drift")
		}
		seenGates[gate.GateID] = true
	}

	catalogRaw, err := inputRaw(inputs, "assurance/formal/obligation-catalog.json")
	if err != nil {
		return nil, err
	}
	var catalog struct {
		Obligations []struct {
			ObligationID string   `json:"obligation_id"`
			SurfaceIDs   []string `json:"surface_ids"`
		} `json:"obligations"`
	}
	if err := json.Unmarshal(catalogRaw, &catalog); err != nil || len(catalog.Obligations) != len(expectedObligationIDs) {
		return nil, fmt.Errorf("formal obligation denominator drift")
	}
	ids := make([]string, len(catalog.Obligations))
	seen := map[string]bool{}
	for i, obligation := range catalog.Obligations {
		if obligation.ObligationID == "" || len(obligation.SurfaceIDs) == 0 || seen[obligation.ObligationID] {
			return nil, fmt.Errorf("duplicate or disconnected formal obligation")
		}
		seen[obligation.ObligationID] = true
		ids[i] = obligation.ObligationID
	}
	if !sort.StringsAreSorted(ids) || !equalStrings(ids, expectedObligationIDs) {
		return nil, fmt.Errorf("formal obligation identity or order drift")
	}

	labRaw, err := inputRaw(inputs, "contracts/laboratory-template.json")
	if err != nil {
		return nil, err
	}
	var laboratory struct {
		RequiredSections []string `json:"required_sections"`
		PublicationRule  string   `json:"publication_rule"`
	}
	if err := json.Unmarshal(labRaw, &laboratory); err != nil || !contains(laboratory.RequiredSections, "independent-replay") || !contains(laboratory.RequiredSections, "public-projection") || laboratory.PublicationRule != "public projection excludes protected cases, outputs, and raw diagnostics" {
		return nil, fmt.Errorf("laboratory projection contract drift")
	}

	for _, name := range []string{"assurance/reviews/human.json", "assurance/reviews/codex.json", "assurance/reviews/reality.json"} {
		raw, err := inputRaw(inputs, name)
		if err != nil {
			return nil, err
		}
		var historical struct {
			Assurance                string `json:"assurance"`
			IndependentReviewClaimed bool   `json:"independent_review_claimed"`
			Status                   string `json:"status"`
		}
		if err := json.Unmarshal(raw, &historical); err != nil || historical.Assurance != Assurance || historical.IndependentReviewClaimed || (name == "assurance/reviews/human.json" && historical.Status != "NOT_EXECUTED") {
			return nil, fmt.Errorf("historical review input %s exceeds its ceiling", name)
		}
	}

	cutoverRaw, err := inputRaw(inputs, "evidence/cutover.json")
	if err != nil {
		return nil, err
	}
	var cutover struct {
		StoryID  string   `json:"story_id"`
		Blockers []string `json:"blockers"`
	}
	if err := json.Unmarshal(cutoverRaw, &cutover); err != nil || cutover.StoryID != "US-026" || len(cutover.Blockers) != 12 {
		return nil, fmt.Errorf("cutover blocker ledger drift")
	}

	firewallRaw, err := inputRaw(inputs, "security/release-firewall.json")
	if err != nil {
		return nil, err
	}
	var firewall struct {
		IncludedClassifications []string `json:"included_classifications"`
		PublicationCapability   bool     `json:"publication_capability"`
	}
	if err := json.Unmarshal(firewallRaw, &firewall); err != nil || firewall.PublicationCapability || !equalStrings(firewall.IncludedClassifications, []string{"PUBLIC", "PUBLIC_DERIVED"}) {
		return nil, fmt.Errorf("release firewall authority drift")
	}
	return ids, nil
}

func makeReceipt(id, role, status string, provider, model, reasoningEffort *string, inputRootSHA string) receipt {
	return receipt{
		Schema: "../../schemas/us027-receipt-1.0.0.schema.json", SchemaVersion: "1.0.0",
		ReceiptID: id, Role: role, Status: status, Provider: provider, Model: model, ReasoningEffort: reasoningEffort,
		DeclaredSubject:             declaredSubjectIdentity{Commit: DeclaredSubjectCommit, Tree: DeclaredSubjectTree},
		SubjectCheckoutVerification: CheckoutNotVerified, CandidateRoot: CandidateRoot,
		ProjectionContractSHA256: ContractSHA256, InputRootSHA256: inputRootSHA,
		MechanicsStatus: MechanicsPass, AcceptanceState: AcceptanceBlocked,
		Independent: false, Accepted: false, ProtectedAccess: false, Assurance: Assurance,
	}
}

func formalMarkdown(ids []string) []byte {
	var buffer bytes.Buffer
	buffer.WriteString("# Formal coverage\n\n")
	buffer.WriteString("Strong independent acceptance: **BLOCKED**\n\n")
	buffer.WriteString("The commit and tree are declared identifiers; the supplied checkout is **NOT_VERIFIED**.\n\n")
	buffer.WriteString("Strong formal coverage: **0/24**. Every obligation remains blocked.\n\n")
	buffer.WriteString("| Obligation | State |\n| --- | --- |\n")
	for _, id := range ids {
		fmt.Fprintf(&buffer, "| `%s` | `BLOCKED` |\n", id)
	}
	return buffer.Bytes()
}

func publicReadme() []byte {
	return []byte("# Local acceptance projection\n\n" +
		"This deterministic projection proves that the owner-relaxed US-027 file mechanics completed for declared Git identifiers. It does not verify that the supplied checkout equals those identifiers.\n\n" +
		"Strong independent acceptance remains blocked: there is no distinct custodian or human review, all 24 formal obligations remain blocked, and the files are local only.\n")
}

func deriveArtifacts(bindings []inputBinding, inputs map[string][]byte) (artifactSet, error) {
	ids, err := validateInputs(inputs)
	if err != nil {
		return artifactSet{}, err
	}
	rootDigest, err := inputRoot(bindings)
	if err != nil {
		return artifactSet{}, err
	}
	openAI, model, effort := "openai", "gpt-5.6-sol", "xhigh"
	receipts := []struct {
		path  string
		value receipt
	}{
		{"assurance/receipts/human.json", makeReceipt("us027.human", "HUMAN_REVIEWER", "NOT_EXECUTED", nil, nil, nil, rootDigest)},
		{"assurance/receipts/codex.json", makeReceipt("us027.codex", "CODEX_OWNER_REVIEW", "OWNER_ATTESTATION_ONLY", &openAI, &model, &effort, rootDigest)},
		{"assurance/receipts/reality.json", makeReceipt("us027.reality", "OWNER_REALITY_REPLAY", "OWNER_ATTESTATION_ONLY", &openAI, &model, &effort, rootDigest)},
	}
	artifacts := make([]namedArtifact, 0, 7)
	digests := make([]artifactDigest, 0, 6)
	for _, entry := range receipts {
		raw, err := canonicalJSON(entry.value)
		if err != nil {
			return artifactSet{}, err
		}
		artifacts = append(artifacts, namedArtifact{path: entry.path, bytes: raw})
		digests = append(digests, artifactDigest{Path: entry.path, SHA256: digest(raw), Bytes: len(raw)})
	}
	formalRaw := formalMarkdown(ids)
	readmeRaw := publicReadme()
	digests = append(digests,
		artifactDigest{Path: "public/formal-coverage.md", SHA256: digest(formalRaw), Bytes: len(formalRaw)},
		artifactDigest{Path: "public/README.md", SHA256: digest(readmeRaw), Bytes: len(readmeRaw)},
	)
	projectionBasis := struct {
		DeclaredSubject declaredSubjectIdentity `json:"declared_subject"`
		SubjectCheckout string                  `json:"subject_checkout"`
		InputRoot       string                  `json:"input_root_sha256"`
		Contract        string                  `json:"projection_contract_sha256"`
		Artifacts       []artifactDigest        `json:"artifacts"`
		Blockers        []string                `json:"blockers"`
		Acceptance      string                  `json:"acceptance_state"`
	}{
		DeclaredSubject: declaredSubjectIdentity{Commit: DeclaredSubjectCommit, Tree: DeclaredSubjectTree},
		SubjectCheckout: CheckoutNotVerified, InputRoot: rootDigest,
		Contract: ContractSHA256, Artifacts: append([]artifactDigest(nil), digests...),
		Blockers: append([]string(nil), blockers...), Acceptance: AcceptanceBlocked,
	}
	basisRaw, err := canonicalJSON(projectionBasis)
	if err != nil {
		return artifactSet{}, err
	}
	projectionRoot := digest(basisRaw)
	summary := Summary{
		MechanicsStatus: MechanicsPass, AcceptanceState: AcceptanceBlocked,
		ChildStoryCount: 26, ChildMechanicsPassed: 26, StrongChildAccepted: 0,
		FormalObligations: 24, FormalStrongAccepted: 0, FormalBlocked: 24,
		SubjectCheckout: CheckoutNotVerified,
	}
	snapshot := publicSnapshot{
		Schema: "../schemas/us027-public-snapshot-1.0.0.schema.json", SchemaVersion: "1.0.0", StoryID: "US-027",
		DeclaredSubject: declaredSubjectIdentity{Commit: DeclaredSubjectCommit, Tree: DeclaredSubjectTree},
		SubjectCheckout: CheckoutNotVerified, ProjectionRoot: projectionRoot,
		Badge: publicBadge, MechanicsStatus: MechanicsPass, AcceptanceState: AcceptanceBlocked,
		ChildStoryCount: 26, ChildMechanicsPassed: 26, StrongChildAccepted: 0,
		FormalObligations: 24, FormalBlocked: 24, FormalStrongAccepted: 0,
		Blockers: append([]string(nil), blockers...), Freshness: publicFreshness, JavaFallback: publicJavaFallback,
		Supersession: publicSupersession, Revocation: publicRevocation, Publication: publicPublication,
		ReplayCommand: "go run ./cmd/projectionctl verify --root .",
	}
	snapshotRaw, err := canonicalJSON(snapshot)
	if err != nil {
		return artifactSet{}, err
	}
	digests = append(digests, artifactDigest{Path: "public/snapshot.json", SHA256: digest(snapshotRaw), Bytes: len(snapshotRaw)})
	replay := replayDocument{
		Schema: "../schemas/us027-independent-replay-1.0.0.schema.json", SchemaVersion: "1.0.0", StoryID: "US-027",
		DeclaredSubject: declaredSubjectIdentity{Commit: DeclaredSubjectCommit, Tree: DeclaredSubjectTree},
		SubjectCheckout: CheckoutNotVerified, CandidateRoot: CandidateRoot,
		ProjectionContractSHA256: ContractSHA256, Inputs: append([]inputBinding(nil), bindings...), InputRootSHA256: rootDigest,
		MechanicsStatus: MechanicsPass, AcceptanceState: AcceptanceBlocked,
		ChildStoryCount: 26, ChildMechanicsPassed: 26, StrongChildAccepted: 0, Children: children(),
		FormalObligations: 24, FormalStrongAccepted: 0, FormalBlocked: 24, Obligations: obligationProjection(ids),
		ProtectedReplay: "NOT_EXECUTED", HumanReview: "NOT_EXECUTED", IndependentCustodian: "NOT_BOUND",
		PublicProjectionRoot: projectionRoot, Artifacts: append([]artifactDigest(nil), digests...),
		Blockers: append([]string(nil), blockers...), Nonclaims: append([]string(nil), nonclaims...),
		Assurance: Assurance, IndependentReviewClaimed: false,
	}
	replayRaw, err := canonicalJSON(replay)
	if err != nil {
		return artifactSet{}, err
	}
	artifacts = append(artifacts,
		namedArtifact{path: "assurance/independent-replay.json", bytes: replayRaw},
		namedArtifact{path: "public/snapshot.json", bytes: snapshotRaw},
		namedArtifact{path: "public/formal-coverage.md", bytes: formalRaw},
		namedArtifact{path: "public/README.md", bytes: readmeRaw},
	)
	return artifactSet{artifacts: artifacts, summary: summary}, nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
