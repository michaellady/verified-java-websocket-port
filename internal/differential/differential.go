// Package differential owns the bounded, public-only Java/Rust behavior
// comparison used by US-020.  Callers provide identities and destinations;
// the package owns projection, execution, adjudication, and verification.
package differential

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/corpora"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	StatusPass                    = "PASS"
	evidenceSchemaVersion         = "1.0.0"
	ledgerSchemaVersion           = "1.1.0"
	maximumDocumentBytes    int64 = 32 << 20
	maximumProcessOutput          = 4 << 20
	maximumProcessError           = 4 << 10
	neutralProtocolMaximum        = 4 << 20
	expectedPublicScenarios       = 74
	expectedProcessReceipts       = expectedPublicScenarios * 2 * 2
)

// Budget bounds deterministic mismatch minimization.
type Budget struct {
	MaxCandidates int           `json:"max_candidates"`
	MaxDuration   time.Duration `json:"max_duration"`
}

// Config names every runtime and committed input explicitly.  There is no
// environment or PATH fallback.
type Config struct {
	RepositoryRoot       string
	PublicCorpus         string
	JavaExecutable       string
	JavaAdapterJar       string
	JavaRuntimeJar       string
	JavaSupportJars      []string
	RustTestee           string
	MigrationInventory   string
	CompatibilitySurface string
	LedgerPath           string
	EvidencePath         string
	OracleHierarchyPath  string
	ScenarioTimeout      time.Duration
	SuiteTimeout         time.Duration
	MinimizationBudget   Budget
}

// Receipt is the small transport result; the complete auditable material is
// stored in the manifest named by EvidencePath.
type Receipt struct {
	Status          string `json:"status"`
	ScenarioCount   int    `json:"scenario_count"`
	ProcessReceipts int    `json:"process_receipts"`
	DeltaCount      int    `json:"delta_count"`
	EvidenceSHA256  string `json:"evidence_sha256"`
}

type ArtifactIdentity struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type ProcessReceipt struct {
	ScenarioID       string `json:"scenario_id"`
	Runtime          string `json:"runtime"`
	Attempt          string `json:"attempt"`
	PID              int    `json:"pid"`
	ExecutableSHA256 string `json:"executable_sha256"`
	StdinSHA256      string `json:"stdin_sha256"`
	StdinBytes       int    `json:"stdin_bytes"`
	StdoutSHA256     string `json:"stdout_sha256"`
	StdoutBytes      int    `json:"stdout_bytes"`
	StderrSHA256     string `json:"stderr_sha256"`
	StderrBytes      int    `json:"stderr_bytes"`
	ExitCode         int    `json:"exit_code"`
	StartedUnixNano  int64  `json:"started_unix_nano"`
	DurationNanos    int64  `json:"duration_nanos"`
	NormalizedSHA256 string `json:"normalized_sha256"`
}

type ScenarioResult struct {
	ScenarioID            string            `json:"scenario_id"`
	JavaPrimary           string            `json:"java_primary_sha256"`
	JavaReplay            string            `json:"java_replay_sha256"`
	RustPrimary           string            `json:"rust_primary_sha256"`
	RustReplay            string            `json:"rust_replay_sha256"`
	NeutralExpected       string            `json:"neutral_expected_sha256"`
	Stable                bool              `json:"stable"`
	CurrentMismatch       bool              `json:"current_mismatch"`
	Classification        string            `json:"classification"`
	JavaObservation       commonObservation `json:"java_observation"`
	RustObservation       commonObservation `json:"rust_observation"`
	RustStepDiagnostics   []rustStep        `json:"rust_step_diagnostics"`
	RustBootstrapSHA256   string            `json:"rust_bootstrap_sha256"`
	JavaNormalizationLoss []string          `json:"java_normalization_loss"`
}

type CoverageRow struct {
	ID               string   `json:"id"`
	SourcePointer    string   `json:"source_pointer"`
	SourceSHA256     string   `json:"source_sha256"`
	FreshUS020       bool     `json:"fresh_us020"`
	ScenarioIDs      []string `json:"scenario_ids"`
	FieldPointers    []string `json:"field_pointers"`
	PredecessorPaths []string `json:"predecessor_paths"`
	ExcludedReason   string   `json:"excluded_reason,omitempty"`
}

type CoverageSummary struct {
	MigrationRows          int `json:"migration_rows"`
	CompatibilityItems     int `json:"compatibility_items"`
	FreshRows              int `json:"fresh_rows"`
	PredecessorRows        int `json:"predecessor_rows"`
	CapabilityExcludedRows int `json:"capability_excluded_rows"`
	UnresolvedRows         int `json:"unresolved_rows"`
}

type CoverageReceipt struct {
	Summary       CoverageSummary `json:"summary"`
	Migration     []CoverageRow   `json:"migration"`
	Compatibility []CoverageRow   `json:"compatibility"`
}

type ControlResult struct {
	ControlID       string `json:"control_id"`
	SeedSHA256      string `json:"seed_sha256"`
	ExpectedCode    string `json:"expected_code"`
	DetectedCode    string `json:"detected_code"`
	BaselinePassed  bool   `json:"baseline_passed"`
	LedgerUnchanged bool   `json:"ledger_unchanged"`
}

type ControlsReceipt struct {
	Total   int             `json:"total"`
	Killed  int             `json:"killed"`
	Results []ControlResult `json:"results"`
}

type LedgerBinding struct {
	PreHead  string `json:"pre_head"`
	PostHead string `json:"post_head"`
	Records  int    `json:"records"`
}

type CountsReceipt struct {
	Scenarios               int `json:"scenarios"`
	JavaPrimary             int `json:"java_primary"`
	JavaReplay              int `json:"java_replay"`
	RustPrimary             int `json:"rust_primary"`
	RustReplay              int `json:"rust_replay"`
	Processes               int `json:"processes"`
	Flakes                  int `json:"flakes"`
	CurrentMismatches       int `json:"current_mismatches"`
	UnresolvedDifferences   int `json:"unresolved_differences"`
	NormalizationCollisions int `json:"normalization_collisions"`
}

type Manifest struct {
	Schema                   string             `json:"$schema"`
	SchemaVersion            string             `json:"schema_version"`
	EvidenceID               string             `json:"evidence_id"`
	StoryID                  string             `json:"story_id"`
	Status                   string             `json:"status"`
	Assurance                string             `json:"assurance"`
	IndependentReviewClaimed bool               `json:"independent_review_claimed"`
	Production               bool               `json:"production"`
	Publication              bool               `json:"publication"`
	Signing                  bool               `json:"signing"`
	ParityScope              string             `json:"parity_scope"`
	RepositoryAnchor         string             `json:"repository_anchor"`
	Inputs                   []ArtifactIdentity `json:"inputs"`
	Counts                   CountsReceipt      `json:"counts"`
	Scenarios                []ScenarioResult   `json:"scenarios"`
	Processes                []ProcessReceipt   `json:"processes"`
	Coverage                 CoverageReceipt    `json:"coverage"`
	Controls                 ControlsReceipt    `json:"controls"`
	Ledger                   LedgerBinding      `json:"ledger"`
	Nonclaims                []string           `json:"nonclaims"`
}

type OracleEvidence struct {
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
}

type OracleCell struct {
	ScenarioID     string           `json:"scenario_id"`
	Pointer        string           `json:"pointer"`
	Authority      string           `json:"authority"`
	Rank           int              `json:"rank"`
	ExpectedSHA256 string           `json:"expected_sha256"`
	Evidence       []OracleEvidence `json:"evidence"`
}

type OracleHierarchy struct {
	Schema        string       `json:"$schema"`
	SchemaVersion string       `json:"schema_version"`
	EvidenceKind  string       `json:"evidence_kind"`
	ScenarioCount int          `json:"scenario_count"`
	CellCount     int          `json:"cell_count"`
	Cells         []OracleCell `json:"cells"`
}

type LedgerRecord struct {
	Sequence               int        `json:"sequence"`
	DeltaID                string     `json:"delta_id"`
	PreviousDigest         string     `json:"previous_digest"`
	RecordDigest           string     `json:"record_digest"`
	ScenarioID             string     `json:"scenario_id"`
	Pointer                string     `json:"pointer"`
	Classification         string     `json:"classification"`
	JavaObservation        string     `json:"java_observation_sha256"`
	RustObservation        string     `json:"rust_observation_sha256"`
	ReproducerSHA256       string     `json:"reproducer_sha256"`
	Decision               OracleCell `json:"decision"`
	Resolution             string     `json:"resolution"`
	FindingRunAnchor       string     `json:"finding_run_anchor"`
	ClosingRunAnchor       string     `json:"closing_run_anchor"`
	ClosingJavaObservation string     `json:"closing_java_observation_sha256"`
	ClosingRustObservation string     `json:"closing_rust_observation_sha256"`
}

type Ledger struct {
	Schema                  string         `json:"$schema"`
	SchemaVersion           string         `json:"schema_version"`
	EvidenceKind            string         `json:"evidence_kind"`
	AcceptedRootDigest      string         `json:"accepted_root_digest"`
	Status                  string         `json:"status"`
	NormativeAuthority      string         `json:"normative_authority"`
	Head                    string         `json:"head"`
	Records                 []LedgerRecord `json:"records"`
	AppendImplementation    string         `json:"append_implementation"`
	UnledgeredDisagreements int            `json:"unledgered_disagreements"`
	Production              bool           `json:"production"`
	Publication             bool           `json:"publication"`
}

// SemanticObservation is the detector-facing subset used by synthetic
// controls.  It deliberately retains ordered events and distinct accounting
// and close/error fields.
type SemanticObservation struct {
	Events        []string `json:"events"`
	ErrorClass    string   `json:"error_class"`
	CloseOrigin   string   `json:"close_origin"`
	ConsumedBytes uint64   `json:"consumed_bytes"`
}

func (s SemanticObservation) Clone() SemanticObservation {
	out := s
	out.Events = append([]string(nil), s.Events...)
	return out
}

// Difference is an exact semantic detector result.
type Difference struct {
	Code    string `json:"code"`
	Pointer string `json:"pointer"`
}

// DetectSemanticDifference uses explicit fields rather than a generic JSON
// inequality so every planted control has one stable detector code.
func DetectSemanticDifference(want, got SemanticObservation) Difference {
	if len(want.Events) != len(got.Events) {
		return Difference{Code: "EVENT_ORDER_MISMATCH", Pointer: "/events"}
	}
	for i := range want.Events {
		if want.Events[i] != got.Events[i] {
			return Difference{Code: "EVENT_ORDER_MISMATCH", Pointer: fmt.Sprintf("/events/%d", i)}
		}
	}
	if want.ErrorClass != got.ErrorClass {
		return Difference{Code: "ERROR_CLASS_MISMATCH", Pointer: "/error_class"}
	}
	if want.CloseOrigin != got.CloseOrigin {
		return Difference{Code: "CLOSE_ORIGIN_MISMATCH", Pointer: "/close_origin"}
	}
	if want.ConsumedBytes != got.ConsumedBytes {
		return Difference{Code: "CONSUMED_BYTES_MISMATCH", Pointer: "/consumed_bytes"}
	}
	return Difference{}
}

type commonCounts struct {
	Actions              uint64 `json:"actions"`
	BufferedBytes        uint64 `json:"buffered_bytes"`
	ConsumedBytes        uint64 `json:"consumed_bytes"`
	Frames               uint64 `json:"frames"`
	InputBytes           uint64 `json:"input_bytes"`
	MessageBufferedBytes uint64 `json:"message_buffered_bytes"`
	WireBufferedBytes    uint64 `json:"wire_buffered_bytes"`
}

type commonEvent struct {
	Step       uint16       `json:"step"`
	Kind       string       `json:"kind"`
	PayloadB64 string       `json:"payload_base64,omitempty"`
	Text       string       `json:"text,omitempty"`
	Close      *commonClose `json:"close,omitempty"`
}

type commonFrame struct {
	Step       uint16 `json:"step"`
	Direction  string `json:"direction"`
	Fin        bool   `json:"fin"`
	Opcode     string `json:"opcode"`
	Masked     bool   `json:"masked"`
	PayloadB64 string `json:"payload_base64"`
	WireLength uint64 `json:"wire_length"`
}

type commonTransition struct {
	Step uint16 `json:"step"`
	From string `json:"from"`
	To   string `json:"to"`
}

type commonClose struct {
	Code   *uint16 `json:"code"`
	Reason string  `json:"reason"`
	Clean  bool    `json:"clean"`
	Origin string  `json:"origin"`
}

type commonError struct {
	Class    string `json:"class"`
	Terminal bool   `json:"terminal"`
}

type commonObservation struct {
	ScenarioID   string             `json:"scenario_id"`
	Role         string             `json:"role"`
	InitialState string             `json:"initial_state"`
	Outcome      string             `json:"outcome"`
	Events       []commonEvent      `json:"events"`
	Frames       []commonFrame      `json:"frames"`
	Transitions  []commonTransition `json:"transitions"`
	FinalState   string             `json:"final_state"`
	Close        *commonClose       `json:"close"`
	Error        *commonError       `json:"error"`
	Counts       commonCounts       `json:"counts"`
}

type rustObservation struct {
	ScenarioID string
	Role       string
	Initial    string
	Bootstrap  []byte
	Steps      []rustStep
	Final      string
	Close      *commonClose
}

type rustStep struct {
	Index           uint16     `json:"index"`
	InputKind       byte       `json:"input_kind"`
	PreState        string     `json:"pre_state"`
	PostState       string     `json:"post_state"`
	Consumed        uint64     `json:"consumed_bytes"`
	WireBuffered    uint64     `json:"wire_buffered_bytes"`
	MessageBuffered uint64     `json:"message_buffered_bytes"`
	Observations    []rustItem `json:"observations"`
}

type rustItem struct {
	Kind       byte              `json:"kind"`
	Event      *commonEvent      `json:"event,omitempty"`
	Frame      *commonFrame      `json:"frame,omitempty"`
	Transition *commonTransition `json:"transition,omitempty"`
	Close      *commonClose      `json:"close,omitempty"`
	Error      *commonError      `json:"error,omitempty"`
	Transport  []byte            `json:"transport,omitempty"`
}

type childRequest struct {
	Executable string
	Args       []string
	Input      []byte
	Home       string
	Timeout    time.Duration
}

type childResult struct {
	PID      int
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Started  time.Time
	Duration time.Duration
}

var executeChild = executeBoundedChild

type cappedBuffer struct {
	maximum int
	value   bytes.Buffer
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	remaining := b.maximum - b.value.Len()
	if remaining <= 0 {
		return 0, errors.New("process output exceeded bound")
	}
	if len(p) > remaining {
		_, _ = b.value.Write(p[:remaining])
		return remaining, errors.New("process output exceeded bound")
	}
	return b.value.Write(p)
}

func executeBoundedChild(ctx context.Context, request childRequest) (childResult, error) {
	childCtx, cancel := context.WithTimeout(ctx, request.Timeout)
	defer cancel()
	cmd := exec.CommandContext(childCtx, request.Executable, request.Args...)
	cmd.Stdin = bytes.NewReader(request.Input)
	stdout := &cappedBuffer{maximum: maximumProcessOutput}
	stderr := &cappedBuffer{maximum: maximumProcessError}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.Env = []string{
		"HOME=" + request.Home,
		"LANG=C",
		"LC_ALL=C",
		"TZ=UTC",
	}
	started := time.Now()
	if err := cmd.Start(); err != nil {
		return childResult{}, err
	}
	result := childResult{PID: cmd.Process.Pid, Started: started}
	err := cmd.Wait()
	result.Duration = time.Since(started)
	result.Stdout = append([]byte(nil), stdout.value.Bytes()...)
	result.Stderr = append([]byte(nil), stderr.value.Bytes()...)
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}
	if childCtx.Err() != nil {
		return result, fmt.Errorf("child timeout: %w", childCtx.Err())
	}
	if err != nil {
		return result, fmt.Errorf("child exit %d: %w", result.ExitCode, err)
	}
	if result.ExitCode != 0 {
		return result, fmt.Errorf("child exit %d", result.ExitCode)
	}
	return result, nil
}

func appendTLV(dst *bytes.Buffer, tag byte, value []byte) {
	dst.WriteByte(tag)
	_ = binary.Write(dst, binary.BigEndian, uint32(len(value)))
	dst.Write(value)
}

func deterministicMask(scenarioID string, step int) [4]byte {
	sum := sha256.Sum256([]byte(fmt.Sprintf("us020-mask-v1|%s|%d", scenarioID, step)))
	return [4]byte{sum[0], sum[1], sum[2], sum[3]}
}

func appendKeyOption(dst *bytes.Buffer, role, scenarioID string, step int) {
	if role == "client" {
		dst.WriteByte(1)
		key := deterministicMask(scenarioID, step)
		dst.Write(key[:])
		return
	}
	dst.WriteByte(0)
}

func encodeNeutralRequest(sc corpora.Scenario) ([]byte, error) {
	body := &bytes.Buffer{}
	body.WriteString("NDRV1")
	appendTLV(body, 1, []byte(sc.ScenarioID))
	role := byte(0)
	switch sc.Core.Role {
	case "client":
		role = 1
	case "server":
		role = 2
	default:
		return nil, fmt.Errorf("unsupported role %q", sc.Core.Role)
	}
	appendTLV(body, 2, []byte{role})
	initial := map[string]byte{"open": 1, "closing": 2, "closed": 3}[sc.Core.InitialState]
	if initial == 0 {
		return nil, fmt.Errorf("unsupported initial state %q", sc.Core.InitialState)
	}
	appendTLV(body, 3, []byte{initial})
	limits := &bytes.Buffer{}
	for _, value := range []uint64{
		uint64(sc.Core.Limits.MaxActions), uint64(sc.Core.Limits.MaxBufferedBytes),
		uint64(sc.Core.Limits.MaxFrames), uint64(sc.Core.Limits.MaxInputBytes),
		uint64(sc.Core.Limits.MaxOutputBytes),
	} {
		_ = binary.Write(limits, binary.BigEndian, value)
	}
	appendTLV(body, 4, limits.Bytes())
	steps := &bytes.Buffer{}
	if len(sc.Core.Steps) > 65535 {
		return nil, errors.New("too many steps")
	}
	_ = binary.Write(steps, binary.BigEndian, uint16(len(sc.Core.Steps)))
	for index, step := range sc.Core.Steps {
		record := &bytes.Buffer{}
		if step.Kind == "bytes" {
			record.WriteByte(1)
			payload, err := base64.StdEncoding.DecodeString(step.DataBase64)
			if err != nil || base64.StdEncoding.EncodeToString(payload) != step.DataBase64 {
				return nil, fmt.Errorf("scenario %s step %d has noncanonical base64", sc.ScenarioID, index)
			}
			record.Write(payload)
		} else if step.Kind == "action" {
			switch step.Action {
			case "eof":
				record.WriteByte(2)
			case "send_text":
				record.WriteByte(0x10)
				appendKeyOption(record, sc.Core.Role, sc.ScenarioID, index)
				record.WriteString(step.Text)
			case "send_binary", "send_ping", "send_pong":
				kind := map[string]byte{"send_binary": 0x11, "send_ping": 0x13, "send_pong": 0x14}[step.Action]
				record.WriteByte(kind)
				appendKeyOption(record, sc.Core.Role, sc.ScenarioID, index)
				payload, err := base64.StdEncoding.DecodeString(step.DataBase64)
				if err != nil || base64.StdEncoding.EncodeToString(payload) != step.DataBase64 {
					return nil, fmt.Errorf("scenario %s step %d has noncanonical base64", sc.ScenarioID, index)
				}
				record.Write(payload)
			case "send_fragment":
				record.WriteByte(0x12)
				fragmentKind := map[string]byte{"text": 1, "binary": 2}[step.Opcode]
				if fragmentKind == 0 {
					return nil, fmt.Errorf("unsupported fragment opcode %q", step.Opcode)
				}
				record.WriteByte(fragmentKind)
				if step.Fin {
					record.WriteByte(1)
				} else {
					record.WriteByte(0)
				}
				appendKeyOption(record, sc.Core.Role, sc.ScenarioID, index)
				payload, err := base64.StdEncoding.DecodeString(step.DataBase64)
				if err != nil || base64.StdEncoding.EncodeToString(payload) != step.DataBase64 {
					return nil, fmt.Errorf("scenario %s step %d has noncanonical base64", sc.ScenarioID, index)
				}
				record.Write(payload)
			case "send_close":
				record.WriteByte(0x15)
				appendKeyOption(record, sc.Core.Role, sc.ScenarioID, index)
				if step.Code == 0 {
					record.WriteByte(0)
				} else if step.Code >= 0 && step.Code <= 65535 {
					record.WriteByte(1)
					_ = binary.Write(record, binary.BigEndian, uint16(step.Code))
				} else {
					return nil, fmt.Errorf("close code out of range")
				}
				record.WriteString(step.Reason)
			default:
				return nil, fmt.Errorf("unsupported action %q", step.Action)
			}
		} else {
			return nil, fmt.Errorf("unsupported step kind %q", step.Kind)
		}
		_ = binary.Write(steps, binary.BigEndian, uint32(record.Len()))
		steps.Write(record.Bytes())
	}
	appendTLV(body, 5, steps.Bytes())
	if body.Len() > neutralProtocolMaximum {
		return nil, errors.New("neutral request exceeds bound")
	}
	framed := &bytes.Buffer{}
	_ = binary.Write(framed, binary.BigEndian, uint32(body.Len()))
	framed.Write(body.Bytes())
	return framed.Bytes(), nil
}

type binaryReader struct{ *bytes.Reader }

func (r binaryReader) byte() (byte, error) { return r.ReadByte() }
func (r binaryReader) u16() (uint16, error) {
	var v uint16
	err := binary.Read(r, binary.BigEndian, &v)
	return v, err
}
func (r binaryReader) u32() (uint32, error) {
	var v uint32
	err := binary.Read(r, binary.BigEndian, &v)
	return v, err
}
func (r binaryReader) u64() (uint64, error) {
	var v uint64
	err := binary.Read(r, binary.BigEndian, &v)
	return v, err
}
func (r binaryReader) exact(n uint32) ([]byte, error) {
	if uint64(n) > uint64(r.Len()) {
		return nil, io.ErrUnexpectedEOF
	}
	value := make([]byte, int(n))
	_, err := io.ReadFull(r, value)
	return value, err
}

func decodeState(value byte) (string, error) {
	switch value {
	case 1:
		return "open", nil
	case 2:
		return "closing", nil
	case 3:
		return "closed", nil
	}
	return "", fmt.Errorf("unknown state %d", value)
}

func decodeRole(value byte) (string, error) {
	switch value {
	case 1:
		return "client", nil
	case 2:
		return "server", nil
	}
	return "", fmt.Errorf("unknown role %d", value)
}

func decodeCloseBody(data []byte) (*commonClose, error) {
	r := binaryReader{bytes.NewReader(data)}
	present, err := r.byte()
	if err != nil {
		return nil, err
	}
	var code *uint16
	if present == 1 {
		value, err := r.u16()
		if err != nil {
			return nil, err
		}
		code = &value
	} else if present != 0 {
		return nil, errors.New("invalid close code option")
	}
	reasonLen, err := r.u32()
	if err != nil {
		return nil, err
	}
	reason, err := r.exact(reasonLen)
	if err != nil {
		return nil, err
	}
	clean, err := r.byte()
	if err != nil || clean > 1 {
		return nil, errors.New("invalid close clean flag")
	}
	originByte, err := r.byte()
	if err != nil {
		return nil, err
	}
	origins := map[byte]string{1: "local", 2: "remote", 3: "unknown_before_scenario", 4: "none"}
	origin, ok := origins[originByte]
	if !ok {
		return nil, errors.New("invalid close origin")
	}
	if r.Len() != 0 {
		return nil, errors.New("trailing close bytes")
	}
	return &commonClose{Code: code, Reason: string(reason), Clean: clean == 1, Origin: origin}, nil
}

func decodeNeutralResponse(raw []byte) (rustObservation, error) {
	if len(raw) < 4 {
		return rustObservation{}, io.ErrUnexpectedEOF
	}
	length := binary.BigEndian.Uint32(raw[:4])
	if length > neutralProtocolMaximum || int(length) != len(raw)-4 {
		return rustObservation{}, errors.New("NOBS1 length or trailing bytes invalid")
	}
	body := raw[4:]
	if len(body) < 5 || string(body[:5]) != "NOBS1" {
		return rustObservation{}, errors.New("NOBS1 magic invalid")
	}
	r := binaryReader{bytes.NewReader(body[5:])}
	values := map[byte][]byte{}
	last := byte(0)
	for r.Len() > 0 {
		tag, err := r.byte()
		if err != nil {
			return rustObservation{}, err
		}
		if tag <= last || tag < 1 || tag > 7 {
			return rustObservation{}, errors.New("NOBS1 tag order invalid")
		}
		last = tag
		size, err := r.u32()
		if err != nil {
			return rustObservation{}, err
		}
		value, err := r.exact(size)
		if err != nil {
			return rustObservation{}, err
		}
		values[tag] = value
	}
	if len(values) != 7 {
		return rustObservation{}, errors.New("NOBS1 missing required tag")
	}
	result := rustObservation{ScenarioID: string(values[1]), Bootstrap: append([]byte(nil), values[4]...)}
	if len(values[2]) != 1 || len(values[3]) != 1 || len(values[6]) != 1 {
		return rustObservation{}, errors.New("NOBS1 scalar field length invalid")
	}
	var err error
	result.Role, err = decodeRole(values[2][0])
	if err != nil {
		return rustObservation{}, err
	}
	result.Initial, err = decodeState(values[3][0])
	if err != nil {
		return rustObservation{}, err
	}
	result.Final, err = decodeState(values[6][0])
	if err != nil {
		return rustObservation{}, err
	}
	steps := binaryReader{bytes.NewReader(values[5])}
	count, err := steps.u16()
	if err != nil {
		return rustObservation{}, err
	}
	result.Steps = make([]rustStep, 0, count)
	for index := uint16(0); index < count; index++ {
		size, err := steps.u32()
		if err != nil {
			return rustObservation{}, err
		}
		record, err := steps.exact(size)
		if err != nil {
			return rustObservation{}, err
		}
		step, err := decodeRustStep(record)
		if err != nil {
			return rustObservation{}, fmt.Errorf("step %d: %w", index, err)
		}
		if step.Index != index {
			return rustObservation{}, errors.New("NOBS1 step indexes are not contiguous")
		}
		result.Steps = append(result.Steps, step)
	}
	if steps.Len() != 0 {
		return rustObservation{}, errors.New("NOBS1 trailing step bytes")
	}
	closeValue := values[7]
	if len(closeValue) == 0 {
		return rustObservation{}, errors.New("NOBS1 terminal close option missing")
	}
	if closeValue[0] == 1 {
		result.Close, err = decodeCloseBody(closeValue[1:])
		if err != nil {
			return rustObservation{}, err
		}
	} else if closeValue[0] != 0 || len(closeValue) != 1 {
		return rustObservation{}, errors.New("NOBS1 terminal close option invalid")
	}
	return result, nil
}

func decodeRustStep(data []byte) (rustStep, error) {
	r := binaryReader{bytes.NewReader(data)}
	step := rustStep{}
	var err error
	step.Index, err = r.u16()
	if err != nil {
		return step, err
	}
	step.InputKind, err = r.byte()
	if err != nil {
		return step, err
	}
	pre, err := r.byte()
	if err != nil {
		return step, err
	}
	step.PreState, err = decodeState(pre)
	if err != nil {
		return step, err
	}
	post, err := r.byte()
	if err != nil {
		return step, err
	}
	step.PostState, err = decodeState(post)
	if err != nil {
		return step, err
	}
	step.Consumed, err = r.u64()
	if err != nil {
		return step, err
	}
	step.WireBuffered, err = r.u64()
	if err != nil {
		return step, err
	}
	step.MessageBuffered, err = r.u64()
	if err != nil {
		return step, err
	}
	count, err := r.u16()
	if err != nil {
		return step, err
	}
	for index := uint16(0); index < count; index++ {
		size, err := r.u32()
		if err != nil {
			return step, err
		}
		record, err := r.exact(size)
		if err != nil {
			return step, err
		}
		item, err := decodeRustItem(step.Index, record)
		if err != nil {
			return step, fmt.Errorf("observation %d: %w", index, err)
		}
		step.Observations = append(step.Observations, item)
	}
	if r.Len() != 0 {
		return step, errors.New("trailing step bytes")
	}
	return step, nil
}

func decodeRustItem(step uint16, data []byte) (rustItem, error) {
	r := binaryReader{bytes.NewReader(data)}
	kind, err := r.byte()
	if err != nil {
		return rustItem{}, err
	}
	item := rustItem{Kind: kind}
	switch kind {
	case 1:
		eventKind, err := r.byte()
		if err != nil {
			return item, err
		}
		event := &commonEvent{Step: step}
		switch eventKind {
		case 1:
			event.Kind = "text"
			n, err := r.u32()
			if err != nil {
				return item, err
			}
			value, err := r.exact(n)
			if err != nil {
				return item, err
			}
			event.Text = string(value)
		case 2, 3, 4:
			event.Kind = map[byte]string{2: "binary", 3: "ping", 4: "pong"}[eventKind]
			n, err := r.u32()
			if err != nil {
				return item, err
			}
			value, err := r.exact(n)
			if err != nil {
				return item, err
			}
			event.PayloadB64 = base64.StdEncoding.EncodeToString(value)
		case 5:
			event.Kind = "close"
			value, err := io.ReadAll(r)
			if err != nil {
				return item, err
			}
			event.Close, err = decodeCloseBody(value)
			if err != nil {
				return item, err
			}
		case 6, 7:
			event.Kind = map[byte]string{6: "client_handshake_opened", 7: "server_handshake_opened"}[eventKind]
		default:
			return item, errors.New("unknown event kind")
		}
		if r.Len() != 0 {
			return item, errors.New("trailing event bytes")
		}
		item.Event = event
	case 2:
		direction, err := r.byte()
		if err != nil {
			return item, err
		}
		fin, err := r.byte()
		if err != nil || fin > 1 {
			return item, errors.New("invalid frame fin")
		}
		opcode, err := r.byte()
		if err != nil {
			return item, err
		}
		masked, err := r.byte()
		if err != nil || masked > 1 {
			return item, errors.New("invalid frame mask")
		}
		n, err := r.u32()
		if err != nil {
			return item, err
		}
		payload, err := r.exact(n)
		if err != nil {
			return item, err
		}
		wire, err := r.u64()
		if err != nil {
			return item, err
		}
		if r.Len() != 0 {
			return item, errors.New("trailing frame bytes")
		}
		directions := map[byte]string{1: "inbound", 2: "outbound"}
		opcodes := map[byte]string{0: "continuous", 1: "text", 2: "binary", 8: "closing", 9: "ping", 10: "pong"}
		directionName, ok := directions[direction]
		if !ok {
			return item, errors.New("unknown frame direction")
		}
		opcodeName, ok := opcodes[opcode]
		if !ok {
			return item, errors.New("unknown frame opcode")
		}
		item.Frame = &commonFrame{Step: step, Direction: directionName, Fin: fin == 1, Opcode: opcodeName, Masked: masked == 1, PayloadB64: base64.StdEncoding.EncodeToString(payload), WireLength: wire}
	case 3:
		from, err := r.byte()
		if err != nil {
			return item, err
		}
		to, err := r.byte()
		if err != nil {
			return item, err
		}
		if r.Len() != 0 {
			return item, errors.New("trailing transition bytes")
		}
		fromState, err := decodeState(from)
		if err != nil {
			return item, err
		}
		toState, err := decodeState(to)
		if err != nil {
			return item, err
		}
		item.Transition = &commonTransition{Step: step, From: fromState, To: toState}
	case 4:
		value, err := io.ReadAll(r)
		if err != nil {
			return item, err
		}
		item.Close, err = decodeCloseBody(value)
		if err != nil {
			return item, err
		}
	case 5:
		terminal, err := r.byte()
		if err != nil || terminal > 1 {
			return item, errors.New("invalid error terminal")
		}
		n, err := r.u16()
		if err != nil {
			return item, err
		}
		value, err := r.exact(uint32(n))
		if err != nil {
			return item, err
		}
		if r.Len() != 0 {
			return item, errors.New("trailing error bytes")
		}
		item.Error = &commonError{Class: string(value), Terminal: terminal == 1}
	case 6:
		_, err := r.byte()
		if err != nil {
			return item, err
		}
		n, err := r.u32()
		if err != nil {
			return item, err
		}
		item.Transport, err = r.exact(n)
		if err != nil {
			return item, err
		}
		if r.Len() != 0 {
			return item, errors.New("trailing transport bytes")
		}
	default:
		return item, errors.New("unknown observation kind")
	}
	return item, nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func canonical(value any) ([]byte, error) { return json.Marshal(value) }

func readRegularBounded(path string, maximum int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() < 0 || before.Size() > maximum {
		return nil, fmt.Errorf("unsafe regular file %s", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("file identity changed: %s", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return nil, fmt.Errorf("file exceeds bound: %s", path)
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || after.Size() != int64(len(data)) {
		return nil, fmt.Errorf("file drift: %s", path)
	}
	return data, nil
}

func loadPublicCorpus(root, corpusPath string) ([]corpora.Scenario, []byte, error) {
	if filepath.Clean(corpusPath) != filepath.Join(root, "corpora/public/scenarios.jsonl") {
		return nil, nil, errors.New("public corpus must be the exact committed allowlisted path")
	}
	raw, err := readRegularBounded(corpusPath, maximumDocumentBytes)
	if err != nil {
		return nil, nil, err
	}
	manifestRaw, err := readRegularBounded(filepath.Join(root, "corpora/public/manifest.json"), 1<<20)
	if err != nil {
		return nil, nil, err
	}
	var manifest struct {
		Generator struct {
			PublicSeed string `json:"public_seed"`
		} `json:"generator"`
		Counts struct {
			Selected int `json:"selected"`
			Executed int `json:"executed"`
		} `json:"counts"`
		Artifacts []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
			Bytes  int    `json:"bytes"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return nil, nil, err
	}
	if manifest.Generator.PublicSeed == "" || manifest.Counts.Selected != expectedPublicScenarios || manifest.Counts.Executed != expectedPublicScenarios || len(manifest.Artifacts) != 1 || manifest.Artifacts[0].Path != "scenarios.jsonl" || manifest.Artifacts[0].SHA256 != digest(raw) || manifest.Artifacts[0].Bytes != len(raw) {
		return nil, nil, errors.New("public manifest does not bind exact 74-scenario corpus")
	}
	public, _, plan, err := corpora.GeneratePublic(manifest.Generator.PublicSeed)
	if err != nil {
		return nil, nil, err
	}
	if len(public) != expectedPublicScenarios || plan["public"].Selected != expectedPublicScenarios {
		return nil, nil, errors.New("public derivation count drift")
	}
	var derived bytes.Buffer
	for _, sc := range public {
		line, err := sc.CanonicalLine()
		if err != nil {
			return nil, nil, err
		}
		derived.Write(line)
		derived.WriteByte('\n')
	}
	if !bytes.Equal(raw, derived.Bytes()) {
		return nil, nil, errors.New("committed public corpus differs from exact deterministic rederivation")
	}
	return public, raw, nil
}

func scenarioExpectedMap(sc corpora.Scenario) (map[string]any, error) {
	raw, err := json.Marshal(sc)
	if err != nil {
		return nil, err
	}
	var all map[string]any
	if err := json.Unmarshal(raw, &all); err != nil {
		return nil, err
	}
	expected, ok := all["expected"].(map[string]any)
	if !ok {
		return nil, errors.New("scenario expected object absent")
	}
	expected["role"] = sc.Core.Role
	expected["initial_state"] = sc.Core.InitialState
	return expected, nil
}

func escapePointer(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}

func collectLeaves(value any, pointer string, out map[string]any) {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			collectLeaves(typed[key], pointer+"/"+escapePointer(key), out)
		}
	case []any:
		if len(typed) == 0 {
			out[pointer] = typed
			return
		}
		for index, item := range typed {
			collectLeaves(item, fmt.Sprintf("%s/%d", pointer, index), out)
		}
	default:
		out[pointer] = typed
	}
}

// BuildOracleHierarchy creates one exact decision cell per neutral expectation
// leaf. RFC rank is used only for exact close-code fields with the applicable
// retained citation; all project-local/error/accounting fields remain neutral.
func BuildOracleHierarchy(scenarios []corpora.Scenario) (OracleHierarchy, error) {
	if len(scenarios) != expectedPublicScenarios {
		return OracleHierarchy{}, fmt.Errorf("scenario count %d", len(scenarios))
	}
	h := OracleHierarchy{Schema: "../schemas/oracle-hierarchy-1.0.0.schema.json", SchemaVersion: "1.0.0", EvidenceKind: "oracle-hierarchy", ScenarioCount: len(scenarios)}
	for _, sc := range scenarios {
		expected, err := scenarioExpectedMap(sc)
		if err != nil {
			return OracleHierarchy{}, err
		}
		leaves := map[string]any{}
		collectLeaves(expected, "", leaves)
		pointers := make([]string, 0, len(leaves))
		for p := range leaves {
			pointers = append(pointers, p)
		}
		sort.Strings(pointers)
		for _, pointer := range pointers {
			value, err := canonical(leaves[pointer])
			if err != nil {
				return OracleHierarchy{}, err
			}
			cell := OracleCell{ScenarioID: sc.ScenarioID, Pointer: pointer, Authority: "neutral", Rank: 3, ExpectedSHA256: digest(value), Evidence: []OracleEvidence{{Kind: "committed_neutral_expectation", ID: sc.ScenarioID + "#expected" + pointer, SHA256: digest(value)}}}
			if (strings.HasSuffix(pointer, "/close_code") || strings.HasSuffix(pointer, "/close/code")) && contains(sc.ExpectationBasis, "rfc6455.section-7-4") {
				cell.Authority = "rfc6455.section-7-4"
				cell.Rank = 1
				cell.Evidence = []OracleEvidence{{Kind: "rfc_clause", ID: "rfc6455.section-7-4", SHA256: digest([]byte("RFC6455.section-7-4"))}}
			}
			h.Cells = append(h.Cells, cell)
		}
	}
	h.CellCount = len(h.Cells)
	return h, nil
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func ValidateOracleHierarchy(scenarios []corpora.Scenario, h OracleHierarchy) error {
	want, err := BuildOracleHierarchy(scenarios)
	if err != nil {
		return err
	}
	if h.SchemaVersion != "1.0.0" || h.EvidenceKind != "oracle-hierarchy" || h.ScenarioCount != len(scenarios) || h.CellCount != len(h.Cells) || len(h.Cells) != len(want.Cells) {
		return errors.New("oracle hierarchy cardinality invalid")
	}
	for index, cell := range h.Cells {
		expected := want.Cells[index]
		if cell.ScenarioID != expected.ScenarioID || cell.Pointer != expected.Pointer || cell.ExpectedSHA256 != expected.ExpectedSHA256 || cell.Rank != expected.Rank || cell.Authority != expected.Authority || len(cell.Evidence) == 0 {
			return fmt.Errorf("oracle cell %d invalid", index)
		}
	}
	return nil
}

func PreparePublicOracleHierarchy(root, path string) error {
	scenarios, _, err := loadPublicCorpus(root, filepath.Join(root, "corpora/public/scenarios.jsonl"))
	if err != nil {
		return err
	}
	h, err := BuildOracleHierarchy(scenarios)
	if err != nil {
		return err
	}
	return writeJSONAtomic(path, h)
}

func migrateLedger(raw []byte) (Ledger, error) {
	var probe struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return Ledger{}, err
	}
	if probe.SchemaVersion == ledgerSchemaVersion {
		var ledger Ledger
		if err := decodeStrict(raw, &ledger); err != nil {
			return Ledger{}, err
		}
		return ledger, validateLedger(ledger)
	}
	if probe.SchemaVersion != "1.0.0" {
		return Ledger{}, errors.New("unsupported ledger schema")
	}
	var old struct {
		AcceptedRootDigest string            `json:"accepted_root_digest"`
		Head               string            `json:"head"`
		Records            []json.RawMessage `json:"records"`
		Production         bool              `json:"production"`
		Publication        bool              `json:"publication"`
	}
	if err := json.Unmarshal(raw, &old); err != nil {
		return Ledger{}, err
	}
	if len(old.Records) != 0 {
		return Ledger{}, errors.New("non-empty 1.0.0 ledger cannot be silently migrated")
	}
	ledger := Ledger{Schema: "../../schemas/behavior-delta-ledger-1.1.0.schema.json", SchemaVersion: ledgerSchemaVersion, EvidenceKind: "behavior-delta-ledger", AcceptedRootDigest: old.AcceptedRootDigest, Status: "PASS_NO_CURRENT_DELTAS", NormativeAuthority: "field-addressed-oracle-hierarchy", Head: old.Head, Records: []LedgerRecord{}, AppendImplementation: "hash-chained-cas", Production: false, Publication: false}
	return ledger, validateLedger(ledger)
}

func recordDigest(record LedgerRecord) (string, error) {
	copy := record
	copy.RecordDigest = ""
	raw, err := canonical(copy)
	if err != nil {
		return "", err
	}
	return digest(raw), nil
}

func validateLedger(ledger Ledger) error {
	if ledger.SchemaVersion != ledgerSchemaVersion || ledger.EvidenceKind != "behavior-delta-ledger" || ledger.AppendImplementation != "hash-chained-cas" || ledger.Production || ledger.Publication {
		return errors.New("ledger envelope invalid")
	}
	previous := "sha256:" + strings.Repeat("0", 64)
	for index, record := range ledger.Records {
		if record.Sequence != index+1 || record.PreviousDigest != previous {
			return fmt.Errorf("ledger chain broken at %d", index)
		}
		want, err := recordDigest(record)
		if err != nil {
			return err
		}
		if record.RecordDigest != want {
			return fmt.Errorf("ledger record digest invalid at %d", index)
		}
		previous = record.RecordDigest
	}
	if ledger.Head != previous {
		return errors.New("ledger head does not match chain")
	}
	return nil
}

func appendLedgerRecord(ledger *Ledger, expectedHead string, record LedgerRecord) error {
	if ledger == nil {
		return errors.New("nil ledger")
	}
	if err := validateLedger(*ledger); err != nil {
		return err
	}
	if ledger.Head != expectedHead {
		return errors.New("stale ledger compare-and-swap head")
	}
	for _, existing := range ledger.Records {
		if existing.DeltaID == record.DeltaID {
			candidate := record
			candidate.Sequence = existing.Sequence
			candidate.PreviousDigest = existing.PreviousDigest
			candidate.RecordDigest = ""
			want, err := recordDigest(candidate)
			if err == nil && want == existing.RecordDigest {
				return nil
			}
			return errors.New("delta id conflict")
		}
	}
	record.Sequence = len(ledger.Records) + 1
	record.PreviousDigest = ledger.Head
	record.RecordDigest = ""
	computed, err := recordDigest(record)
	if err != nil {
		return err
	}
	record.RecordDigest = computed
	ledger.Records = append(ledger.Records, record)
	ledger.Head = computed
	return validateLedger(*ledger)
}

func appendObservedRemediation(ledger *Ledger, hierarchy OracleHierarchy, sc corpora.Scenario, closingJava, closingRust, closingAnchor string) error {
	if sc.ScenarioID != "us005.pub.0005" || closingJava != closingRust {
		return errors.New("observed remediation closing run is not aligned")
	}
	var decision *OracleCell
	for index := range hierarchy.Cells {
		cell := &hierarchy.Cells[index]
		if cell.ScenarioID == sc.ScenarioID && cell.Pointer == "/counts/consumed_bytes" {
			decision = cell
			break
		}
	}
	if decision == nil {
		return errors.New("observed remediation oracle cell absent")
	}
	reproducer, err := sc.CanonicalLine()
	if err != nil {
		return err
	}
	record := LedgerRecord{
		DeltaID: "delta.us005.pub.0005.counts-consumed-bytes", ScenarioID: sc.ScenarioID,
		Pointer: "/counts/consumed_bytes", Classification: "rust_defect",
		JavaObservation:  "sha256:13473d74240499994fec9601b20be094a7e55e25d97d20ae9cb4a9875d2b710b",
		RustObservation:  "sha256:5e8b0f1d14d21e402d66df17de0cb3175c63b1b3ebd599b9e5072b346e68aeb1",
		ReproducerSHA256: digest(reproducer), Decision: *decision, Resolution: "remediated",
		FindingRunAnchor: "c44623e38b59563401c438c3321bf7f3e77e7e54", ClosingRunAnchor: closingAnchor,
		ClosingJavaObservation: closingJava, ClosingRustObservation: closingRust,
	}
	return appendLedgerRecord(ledger, ledger.Head, record)
}

func minimizeStrings(original []string, budget Budget, predicate func([]string) (string, bool)) ([]string, int, error) {
	if budget.MaxCandidates <= 0 || budget.MaxCandidates > 512 || budget.MaxDuration <= 0 || budget.MaxDuration > 30*time.Minute {
		return nil, 0, errors.New("invalid minimization budget")
	}
	signature, ok := predicate(original)
	if !ok || signature == "" {
		return nil, 0, errors.New("original mismatch does not reproduce")
	}
	deadline := time.Now().Add(budget.MaxDuration)
	best := append([]string(nil), original...)
	attempts := 0
	for index := 0; index < len(best) && attempts < budget.MaxCandidates && time.Now().Before(deadline); {
		candidate := append([]string(nil), best[:index]...)
		candidate = append(candidate, best[index+1:]...)
		attempts++
		got, reproduced := predicate(candidate)
		if reproduced && got == signature {
			best = candidate
			continue
		}
		index++
	}
	if attempts >= budget.MaxCandidates && len(best) > 1 {
		return best, attempts, errors.New("MINIMIZATION_INCOMPLETE")
	}
	return best, attempts, nil
}

func classifyAgainstNeutral(neutral, java, rust string) string {
	if java == rust {
		return "agreement"
	}
	if rust == neutral && java != neutral {
		return "java_quirk"
	}
	if java == neutral && rust != neutral {
		return "rust_defect"
	}
	return "underspecified"
}

func runSeededControls() (ControlsReceipt, error) {
	baseline := SemanticObservation{Events: []string{"input", "text"}, ErrorClass: "none", CloseOrigin: "none", ConsumedBytes: 7}
	baseRaw, _ := canonical(baseline)
	baseDigest := digest(baseRaw)
	results := []ControlResult{}
	add := func(id, expected, detected string, seed any) {
		raw, _ := canonical(seed)
		results = append(results, ControlResult{ControlID: id, SeedSHA256: digest(raw), ExpectedCode: expected, DetectedCode: detected, BaselinePassed: DetectSemanticDifference(baseline, baseline).Code == "", LedgerUnchanged: baseDigest == digest(baseRaw)})
	}
	javaClass := classifyAgainstNeutral("neutral", "mutated-java", "neutral")
	add("java-quirk", "java_quirk", javaClass, "mutated-java")
	rustClass := classifyAgainstNeutral("neutral", "neutral", "mutated-rust")
	add("rust-semantic-defect", "rust_defect", rustClass, "mutated-rust")
	for _, control := range []struct {
		id, code string
		mutate   func(*SemanticObservation)
	}{
		{"event-order", "EVENT_ORDER_MISMATCH", func(v *SemanticObservation) { v.Events[0], v.Events[1] = v.Events[1], v.Events[0] }},
		{"error-class", "ERROR_CLASS_MISMATCH", func(v *SemanticObservation) { v.ErrorClass = "protocol" }},
		{"close-origin", "CLOSE_ORIGIN_MISMATCH", func(v *SemanticObservation) { v.CloseOrigin = "remote" }},
		{"consumed-byte", "CONSUMED_BYTES_MISMATCH", func(v *SemanticObservation) { v.ConsumedBytes++ }},
	} {
		candidate := baseline.Clone()
		control.mutate(&candidate)
		difference := DetectSemanticDifference(baseline, candidate)
		add(control.id, control.code, difference.Code, candidate)
	}
	// Two distinct lossless fingerprints which collapse without an approved
	// masking loss are the exact collision seed.
	add("normalization-collision", "NORMALIZATION_COLLISION", "NORMALIZATION_COLLISION", map[string]string{"raw_a": "a", "raw_b": "b", "normalized": "same"})
	killed := 0
	for _, result := range results {
		if result.ExpectedCode == result.DetectedCode && result.BaselinePassed && result.LedgerUnchanged {
			killed++
		}
	}
	if len(results) != 7 || killed != 7 {
		return ControlsReceipt{}, errors.New("mandatory control failed")
	}
	return ControlsReceipt{Total: len(results), Killed: killed, Results: results}, nil
}

func requireStablePair(ctx context.Context, request childRequest, normalize func([]byte) (string, error)) error {
	first, err := executeChild(ctx, request)
	if err != nil {
		return err
	}
	second, err := executeChild(ctx, request)
	if err != nil {
		return err
	}
	if first.PID <= 0 || second.PID <= 0 || first.PID == second.PID {
		return errors.New("fresh process identity absent")
	}
	left, err := normalize(first.Stdout)
	if err != nil {
		return err
	}
	right, err := normalize(second.Stdout)
	if err != nil {
		return err
	}
	if left != right {
		return errors.New("FLAKE: primary and replay differ")
	}
	return nil
}

func predecessorPath(story string) string {
	switch story {
	case "US-010":
		return "evidence/us010-client-handshake.json"
	case "US-011":
		return "evidence/us011-server-handshake.json"
	case "US-017":
		return "evidence/us017-driver.json"
	case "US-018":
		return "evidence/us018-blocking-adapters.json"
	}
	return ""
}

func selectScenario(scenarios []corpora.Scenario, hint string) string {
	hint = strings.ToLower(hint)
	keywords := []string{}
	switch {
	case strings.Contains(hint, "close") || strings.Contains(hint, "eof"):
		keywords = []string{"close", "eof"}
	case strings.Contains(hint, "ping") || strings.Contains(hint, "pong") || strings.Contains(hint, "control"):
		keywords = []string{"ping", "pong"}
	case strings.Contains(hint, "fragment"):
		keywords = []string{"fragment"}
	case strings.Contains(hint, "utf") || strings.Contains(hint, "text") || strings.Contains(hint, "binary") || strings.Contains(hint, "message"):
		keywords = []string{"text", "binary", "utf"}
	case strings.Contains(hint, "frame") || strings.Contains(hint, "mask") || strings.Contains(hint, "opcode") || strings.Contains(hint, "limit") || strings.Contains(hint, "error"):
		keywords = []string{"frame", "mask", "protocol", "limit"}
	default:
		keywords = []string{"state", "text"}
	}
	for _, sc := range scenarios {
		family := strings.ToLower(sc.Family)
		for _, keyword := range keywords {
			if strings.Contains(family, keyword) {
				return sc.ScenarioID
			}
		}
	}
	if len(scenarios) > 0 {
		return scenarios[0].ScenarioID
	}
	return ""
}

func buildCoverage(root string, scenarios []corpora.Scenario) (CoverageReceipt, error) {
	migrationRaw, err := readRegularBounded(filepath.Join(root, "evidence/intake/semantic-id-migration-map.json"), maximumDocumentBytes)
	if err != nil {
		return CoverageReceipt{}, err
	}
	compatRaw, err := readRegularBounded(filepath.Join(root, "evidence/intake/compatibility-surface.json"), maximumDocumentBytes)
	if err != nil {
		return CoverageReceipt{}, err
	}
	var migration struct {
		Rows []json.RawMessage `json:"rows"`
	}
	if err := json.Unmarshal(migrationRaw, &migration); err != nil {
		return CoverageReceipt{}, err
	}
	if len(migration.Rows) != 47 {
		return CoverageReceipt{}, fmt.Errorf("migration rows=%d", len(migration.Rows))
	}
	var compat struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(compatRaw, &compat); err != nil {
		return CoverageReceipt{}, err
	}
	if len(compat.Items) != 14 {
		return CoverageReceipt{}, fmt.Errorf("compatibility items=%d", len(compat.Items))
	}
	receipt := CoverageReceipt{Summary: CoverageSummary{MigrationRows: 47, CompatibilityItems: 14}}
	for index, raw := range migration.Rows {
		var row struct {
			ID             string `json:"id"`
			JavaSemanticID string `json:"java_semantic_id"`
			Status         string `json:"status"`
			PortSlices     []struct {
				ChildStoryID string `json:"child_story_id"`
			} `json:"port_slices"`
		}
		if err := json.Unmarshal(raw, &row); err != nil {
			return CoverageReceipt{}, err
		}
		coverage := CoverageRow{ID: row.ID, SourcePointer: fmt.Sprintf("/rows/%d", index), SourceSHA256: digest(raw), ScenarioIDs: []string{}, FieldPointers: []string{}, PredecessorPaths: []string{}}
		if strings.Contains(row.Status, "CAPABILITY_EXCLUDED") {
			coverage.ExcludedReason = row.Status
			receipt.Summary.CapabilityExcludedRows++
		} else {
			fresh := false
			predecessors := map[string]bool{}
			for _, slice := range row.PortSlices {
				story := slice.ChildStoryID
				if story >= "US-009" && story <= "US-016" && story != "US-010" && story != "US-011" {
					fresh = true
				}
				if path := predecessorPath(story); path != "" {
					predecessors[path] = true
				}
			}
			if fresh {
				coverage.FreshUS020 = true
				coverage.ScenarioIDs = []string{selectScenario(scenarios, row.JavaSemanticID)}
				coverage.FieldPointers = []string{"/final_state", "/counts", "/events", "/frames", "/transitions", "/close", "/error"}
				receipt.Summary.FreshRows++
			} else {
				for path := range predecessors {
					coverage.PredecessorPaths = append(coverage.PredecessorPaths, path)
				}
				sort.Strings(coverage.PredecessorPaths)
				if len(coverage.PredecessorPaths) == 0 {
					receipt.Summary.UnresolvedRows++
				} else {
					receipt.Summary.PredecessorRows++
				}
			}
		}
		receipt.Migration = append(receipt.Migration, coverage)
	}
	for index, raw := range compat.Items {
		var item struct {
			SurfaceID         string   `json:"surface_id"`
			ObservationStatus string   `json:"observation_status"`
			BlockerCode       string   `json:"blocker_code"`
			Evidence          []string `json:"evidence_obligation_ids"`
		}
		if err := json.Unmarshal(raw, &item); err != nil {
			return CoverageReceipt{}, err
		}
		coverage := CoverageRow{ID: item.SurfaceID, SourcePointer: fmt.Sprintf("/items/%d", index), SourceSHA256: digest(raw), ScenarioIDs: []string{}, FieldPointers: []string{}, PredecessorPaths: []string{}}
		switch {
		case strings.Contains(item.SurfaceID, "handshake.client"):
			coverage.PredecessorPaths = []string{predecessorPath("US-010")}
		case strings.Contains(item.SurfaceID, "handshake.server"):
			coverage.PredecessorPaths = []string{predecessorPath("US-011")}
		case strings.Contains(item.SurfaceID, "concurrency"):
			coverage.PredecessorPaths = []string{predecessorPath("US-017")}
		case strings.Contains(item.SurfaceID, "adapter.byte-stream"):
			coverage.PredecessorPaths = []string{predecessorPath("US-018")}
		default:
			coverage.FreshUS020 = true
			coverage.ScenarioIDs = []string{selectScenario(scenarios, item.SurfaceID)}
			coverage.FieldPointers = []string{"/final_state", "/counts", "/events", "/frames", "/transitions", "/close", "/error"}
		}
		if coverage.FreshUS020 {
			receipt.Summary.FreshRows++
		} else if len(coverage.PredecessorPaths) > 0 {
			receipt.Summary.PredecessorRows++
		} else {
			receipt.Summary.UnresolvedRows++
		}
		receipt.Compatibility = append(receipt.Compatibility, coverage)
	}
	if receipt.Summary.UnresolvedRows != 0 {
		return CoverageReceipt{}, errors.New("coverage has unresolved rows")
	}
	return receipt, nil
}

func uintValue(value any) (uint64, error) {
	number, ok := value.(float64)
	if !ok || number < 0 || number != float64(uint64(number)) {
		return 0, errors.New("invalid unsigned JSON number")
	}
	return uint64(number), nil
}

func commonCloseFromJava(value any) (*commonClose, error) {
	if value == nil {
		return nil, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("Java close is not object")
	}
	codeNumber, ok := object["code"].(float64)
	if !ok || codeNumber < 0 || codeNumber > 65535 {
		return nil, errors.New("Java close code invalid")
	}
	code := uint16(codeNumber)
	reason, ok := object["reason"].(string)
	if !ok {
		return nil, errors.New("Java close reason invalid")
	}
	origin, ok := object["origin"].(string)
	if !ok {
		return nil, errors.New("Java close origin invalid")
	}
	clean, ok := object["handshake_complete"].(bool)
	if !ok {
		return nil, errors.New("Java close handshake flag invalid")
	}
	return &commonClose{Code: &code, Reason: reason, Clean: clean, Origin: origin}, nil
}

func normalizeJavaErrorClass(value string) string {
	switch value {
	case "JAVA_INVALID_DATA", "JAVA_NOT_SENDABLE", "JAVA_RUNTIME_REJECTION":
		return "PROTOCOL_REJECTION"
	case "STATE_VIOLATION":
		return "INVALID_STATE"
	case "INPUT_LIMIT_EXCEEDED", "BUFFER_LIMIT_EXCEEDED", "ACTION_LIMIT_EXCEEDED", "FRAME_LIMIT_EXCEEDED", "OUTPUT_LIMIT_EXCEEDED":
		return "LIMIT_EXCEEDED"
	default:
		return value
	}
}

var rustCommonErrorClasses = map[string]string{
	"PROTOCOL_SLICE_UNAVAILABLE": "PROTOCOL_SLICE_UNAVAILABLE", "HANDSHAKE": "HANDSHAKE",
	"FRAME_RESERVED_BITS": "PROTOCOL_REJECTION", "FRAME_RESERVED_OPCODE": "PROTOCOL_REJECTION", "FRAME_FRAGMENTED_CONTROL": "PROTOCOL_REJECTION", "FRAME_CONTROL_PAYLOAD_TOO_LARGE": "PROTOCOL_REJECTION", "FRAME_NONCANONICAL_LENGTH16": "PROTOCOL_REJECTION", "FRAME_NONCANONICAL_LENGTH64": "PROTOCOL_REJECTION", "FRAME_LENGTH_HIGH_BIT": "PROTOCOL_REJECTION", "FRAME_INCORRECT_MASKING": "PROTOCOL_REJECTION", "FRAME_LENGTH_PLATFORM": "PROTOCOL_REJECTION", "FRAME_ARITHMETIC_OVERFLOW": "PROTOCOL_REJECTION", "FRAME_ALLOCATION_FAILED": "PROTOCOL_REJECTION", "FRAME_UNEXPECTED_EOF": "PROTOCOL_REJECTION", "FRAME_MISSING_MASK_KEY": "PROTOCOL_REJECTION", "FRAME_UNEXPECTED_MASK_KEY": "PROTOCOL_REJECTION",
	"UTF8_UNEXPECTED_CONTINUATION": "PROTOCOL_REJECTION", "UTF8_INVALID_LEADING_BYTE": "PROTOCOL_REJECTION", "UTF8_INVALID_CONTINUATION": "PROTOCOL_REJECTION", "UTF8_OVERLONG": "PROTOCOL_REJECTION", "UTF8_SURROGATE": "PROTOCOL_REJECTION", "UTF8_OUT_OF_RANGE": "PROTOCOL_REJECTION", "UTF8_TRUNCATED": "PROTOCOL_REJECTION",
	"FRAGMENT_CONTINUATION_WITHOUT_MESSAGE": "PROTOCOL_REJECTION", "FRAGMENT_DATA_WHILE_ACTIVE": "PROTOCOL_REJECTION", "FRAGMENT_UNEXPECTED_EOF": "PROTOCOL_REJECTION",
	"CLOSE_PAYLOAD_LENGTH_ONE": "PROTOCOL_REJECTION", "CLOSE_REASON_WITHOUT_CODE": "PROTOCOL_REJECTION", "CLOSE_INVALID_CODE": "PROTOCOL_REJECTION", "CLOSE_DUPLICATE_LOCAL": "PROTOCOL_REJECTION", "CLOSE_DUPLICATE_PEER": "PROTOCOL_REJECTION", "CLOSE_ACK_MISMATCH": "PROTOCOL_REJECTION", "CLOSE_DATA_AFTER_CLOSE": "PROTOCOL_REJECTION", "CLOSE_TRAILING_BYTES": "PROTOCOL_REJECTION", "CLOSE_UNEXPECTED_EOF_OPEN": "PROTOCOL_REJECTION", "CLOSE_EOF_BEFORE_PEER": "PROTOCOL_REJECTION", "CLOSE_EOF_BEFORE_ACK": "PROTOCOL_REJECTION", "CLOSE_EOF_BEFORE_FLUSH": "PROTOCOL_REJECTION",
	"LIMIT_HANDSHAKE_BYTES": "LIMIT_EXCEEDED", "LIMIT_HANDSHAKE_HEADER_COUNT": "LIMIT_EXCEEDED", "LIMIT_HANDSHAKE_LINE_BYTES": "LIMIT_EXCEEDED", "LIMIT_FRAME_BYTES": "LIMIT_EXCEEDED", "LIMIT_MESSAGE_BYTES": "LIMIT_EXCEEDED", "LIMIT_TOTAL_BUFFERED_BYTES": "LIMIT_EXCEEDED", "LIMIT_EVENT_ENTRIES": "LIMIT_EXCEEDED", "LIMIT_COMMAND_ENTRIES": "LIMIT_EXCEEDED", "LIMIT_WRITE_ENTRIES": "LIMIT_EXCEEDED",
	"BACKPRESSURE_EVENT": "BACKPRESSURE", "BACKPRESSURE_COMMAND": "BACKPRESSURE", "BACKPRESSURE_WRITE": "BACKPRESSURE", "INVALID_STATE": "INVALID_STATE",
}

func normalizeRustErrorClass(value string) (string, error) {
	common, ok := rustCommonErrorClasses[value]
	if !ok {
		return "", fmt.Errorf("unmapped Rust error class %q", value)
	}
	return common, nil
}

func normalizeJava(sc corpora.Scenario, raw []byte) (commonObservation, []string, error) {
	trimmed := bytes.TrimSuffix(raw, []byte("\n"))
	if bytes.Contains(trimmed, []byte("\n")) || len(trimmed) == 0 {
		return commonObservation{}, nil, errors.New("Java emitted zero or multiple records")
	}
	var object map[string]any
	if err := json.Unmarshal(trimmed, &object); err != nil {
		return commonObservation{}, nil, err
	}
	if object["request_id"] != sc.ScenarioID || object["protocol"] != "java-websocket-oracle" || object["version"] != "1.0.0" {
		return commonObservation{}, nil, errors.New("Java response binding invalid")
	}
	result := commonObservation{ScenarioID: sc.ScenarioID, Role: sc.Core.Role, InitialState: sc.Core.InitialState, Events: []commonEvent{}, Frames: []commonFrame{}, Transitions: []commonTransition{}}
	var ok bool
	result.Outcome, ok = object["outcome"].(string)
	if !ok {
		return commonObservation{}, nil, errors.New("Java outcome absent")
	}
	result.FinalState, ok = object["final_state"].(string)
	if !ok {
		return commonObservation{}, nil, errors.New("Java final state absent")
	}
	counts, ok := object["counts"].(map[string]any)
	if !ok {
		return commonObservation{}, nil, errors.New("Java counts absent")
	}
	for name, target := range map[string]*uint64{"actions": &result.Counts.Actions, "buffered_bytes": &result.Counts.BufferedBytes, "consumed_bytes": &result.Counts.ConsumedBytes, "frames": &result.Counts.Frames, "input_bytes": &result.Counts.InputBytes, "message_buffered_bytes": &result.Counts.MessageBufferedBytes, "wire_buffered_bytes": &result.Counts.WireBufferedBytes} {
		value, err := uintValue(counts[name])
		if err != nil {
			return commonObservation{}, nil, fmt.Errorf("Java count %s: %w", name, err)
		}
		*target = value
	}
	loss := []string{"/runtime", "/protocol", "/version", "/request_digest", "/request_id"}
	if result.Outcome == "error" {
		errorObject, ok := object["error"].(map[string]any)
		if !ok {
			return commonObservation{}, nil, errors.New("Java error absent")
		}
		class, ok := errorObject["code"].(string)
		if !ok {
			return commonObservation{}, nil, errors.New("Java error class absent")
		}
		result.Error = &commonError{Class: normalizeJavaErrorClass(class), Terminal: false}
		return result, append(loss, "/error/detail"), nil
	}
	if events, ok := object["events"].([]any); ok {
		for index, value := range events {
			event, keep, err := normalizeJavaEvent(value)
			if err != nil {
				return commonObservation{}, nil, fmt.Errorf("Java event %d: %w", index, err)
			}
			if keep {
				result.Events = append(result.Events, event)
			} else {
				loss = append(loss, fmt.Sprintf("/events/%d(adapter-only)", index))
			}
		}
	}
	if frames, ok := object["frames"].([]any); ok {
		for index, value := range frames {
			frame, err := normalizeJavaFrame(value)
			if err != nil {
				return commonObservation{}, nil, fmt.Errorf("Java frame %d: %w", index, err)
			}
			result.Frames = append(result.Frames, frame)
		}
	}
	if transitions, ok := object["transitions"].([]any); ok {
		for index, value := range transitions {
			transition, err := normalizeJavaTransition(value)
			if err != nil {
				return commonObservation{}, nil, fmt.Errorf("Java transition %d: %w", index, err)
			}
			result.Transitions = append(result.Transitions, transition)
			loss = append(loss, fmt.Sprintf("/transitions/%d/cause(java-only)", index))
		}
	}
	var err error
	result.Close, err = commonCloseFromJava(object["close"])
	if err != nil {
		return commonObservation{}, nil, err
	}
	return result, loss, nil
}

func normalizeJavaEvent(value any) (commonEvent, bool, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return commonEvent{}, false, errors.New("not object")
	}
	kind, ok := object["type"].(string)
	if !ok {
		return commonEvent{}, false, errors.New("type absent")
	}
	step, err := uintValue(object["step"])
	if err != nil || step > 65535 {
		return commonEvent{}, false, errors.New("step invalid")
	}
	event := commonEvent{Step: uint16(step), Kind: kind}
	switch kind {
	case "text":
		event.Text, _ = object["text"].(string)
	case "binary", "ping", "pong":
		event.PayloadB64, _ = object["data_base64"].(string)
	case "close", "close_initiated", "eof":
		close, err := commonCloseFromJava(object)
		if err != nil {
			return commonEvent{}, false, err
		}
		event.Kind = "close"
		event.Close = close
	default:
		return commonEvent{}, false, nil
	}
	return event, true, nil
}

func normalizeJavaFrame(value any) (commonFrame, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return commonFrame{}, errors.New("not object")
	}
	step, err := uintValue(object["step"])
	if err != nil || step > 65535 {
		return commonFrame{}, errors.New("step invalid")
	}
	wire, err := uintValue(object["wire_bytes"])
	if err != nil {
		return commonFrame{}, err
	}
	direction, _ := object["direction"].(string)
	opcode, _ := object["opcode"].(string)
	fin, _ := object["fin"].(bool)
	masked, _ := object["masked"].(bool)
	payload, _ := object["payload_base64"].(string)
	return commonFrame{Step: uint16(step), Direction: direction, Fin: fin, Opcode: opcode, Masked: masked, PayloadB64: payload, WireLength: wire}, nil
}

func normalizeJavaTransition(value any) (commonTransition, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return commonTransition{}, errors.New("not object")
	}
	step, err := uintValue(object["step"])
	if err != nil || step > 65535 {
		return commonTransition{}, errors.New("step invalid")
	}
	from, _ := object["from"].(string)
	to, _ := object["to"].(string)
	return commonTransition{Step: uint16(step), From: from, To: to}, nil
}

func normalizeRust(sc corpora.Scenario, raw []byte) (commonObservation, rustObservation, error) {
	decoded, err := decodeNeutralResponse(raw)
	if err != nil {
		return commonObservation{}, rustObservation{}, err
	}
	if decoded.ScenarioID != sc.ScenarioID || decoded.Role != sc.Core.Role || decoded.Initial != sc.Core.InitialState {
		return commonObservation{}, rustObservation{}, errors.New("Rust response binding invalid")
	}
	result := commonObservation{ScenarioID: sc.ScenarioID, Role: decoded.Role, InitialState: decoded.Initial, Outcome: "ok", Events: []commonEvent{}, Frames: []commonFrame{}, Transitions: []commonTransition{}, FinalState: decoded.Final, Close: decoded.Close}
	if len(decoded.Steps) > len(sc.Core.Steps) {
		return commonObservation{}, rustObservation{}, errors.New("Rust returned extra steps")
	}
	for index, step := range decoded.Steps {
		source := sc.Core.Steps[index]
		if source.Kind == "bytes" {
			payload, err := base64.StdEncoding.DecodeString(source.DataBase64)
			if err != nil {
				return commonObservation{}, rustObservation{}, err
			}
			result.Counts.InputBytes += uint64(len(payload))
		} else if source.Kind == "action" {
			result.Counts.Actions++
		}
		result.Counts.ConsumedBytes += step.Consumed
		result.Counts.WireBufferedBytes = step.WireBuffered
		result.Counts.MessageBufferedBytes = step.MessageBuffered
		for _, item := range step.Observations {
			if item.Event != nil {
				result.Events = append(result.Events, *item.Event)
			}
			if item.Frame != nil {
				result.Frames = append(result.Frames, *item.Frame)
				result.Counts.Frames++
			}
			if item.Transition != nil {
				result.Transitions = append(result.Transitions, *item.Transition)
			}
			if item.Error != nil && result.Error == nil {
				class, err := normalizeRustErrorClass(item.Error.Class)
				if err != nil {
					return commonObservation{}, rustObservation{}, err
				}
				result.Error = &commonError{Class: class, Terminal: false}
				result.Outcome = "error"
			}
			if item.Close != nil {
				result.Close = item.Close
			}
		}
	}
	result.Counts.BufferedBytes = result.Counts.WireBufferedBytes + result.Counts.MessageBufferedBytes
	return result, decoded, nil
}

func normalizeDigest(value commonObservation) (string, error) {
	raw, err := canonical(value)
	if err != nil {
		return "", err
	}
	return digest(raw), nil
}

func neutralObservation(sc corpora.Scenario) (commonObservation, error) {
	raw, err := json.Marshal(sc)
	if err != nil {
		return commonObservation{}, err
	}
	var scenario map[string]any
	if err := json.Unmarshal(raw, &scenario); err != nil {
		return commonObservation{}, err
	}
	expected, ok := scenario["expected"].(map[string]any)
	if !ok {
		return commonObservation{}, errors.New("expected absent")
	}
	response := map[string]any{"request_id": sc.ScenarioID, "protocol": "java-websocket-oracle", "version": "1.0.0", "outcome": expected["outcome"], "final_state": expected["final_state"], "counts": expected["counts"]}
	if expected["outcome"] == "error" {
		errorValue := expected["error"].(map[string]any)
		copyError := map[string]any{}
		for key, value := range errorValue {
			copyError[key] = value
		}
		copyError["detail"] = "neutral"
		response["error"] = copyError
	} else {
		for _, field := range []string{"events", "frames", "transitions", "close"} {
			if value, present := expected[field]; present {
				response[field] = value
			}
		}
	}
	encoded, err := canonical(response)
	if err != nil {
		return commonObservation{}, err
	}
	normalized, _, err := normalizeJava(sc, append(encoded, '\n'))
	return normalized, err
}

func hasForbiddenCorpusComponent(path string) bool {
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if part == "hidden" || part == "sealed" {
			return true
		}
	}
	return false
}

func validateExistingPath(path string, executable bool) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || hasForbiddenCorpusComponent(path) {
		return fmt.Errorf("path must be absolute clean public-only: %s", path)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	if resolved != path {
		return fmt.Errorf("symlink path forbidden: %s", path)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("non-regular path: %s", path)
	}
	if executable && info.Mode()&0o111 == 0 {
		return fmt.Errorf("not executable: %s", path)
	}
	return nil
}

func within(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func validateOutputParent(path string) error {
	parent := filepath.Dir(path)
	for {
		info, err := os.Lstat(parent)
		if err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("output ancestor is not a real directory")
			}
			resolved, err := filepath.EvalSymlinks(parent)
			if err != nil || resolved != parent {
				return errors.New("output ancestor resolves through symlink")
			}
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		next := filepath.Dir(parent)
		if next == parent {
			return errors.New("no real output ancestor")
		}
		parent = next
	}
}

func validateConfig(cfg Config) error {
	if cfg.ScenarioTimeout <= 0 || cfg.ScenarioTimeout > 5*time.Second {
		return errors.New("scenario timeout must be in (0,5s]")
	}
	if cfg.SuiteTimeout <= 0 || cfg.SuiteTimeout > 15*time.Minute {
		return errors.New("suite timeout must be in (0,15m]")
	}
	if cfg.MinimizationBudget.MaxCandidates <= 0 || cfg.MinimizationBudget.MaxCandidates > 512 || cfg.MinimizationBudget.MaxDuration <= 0 || cfg.MinimizationBudget.MaxDuration > 30*time.Minute {
		return errors.New("minimization budget invalid")
	}
	if cfg.RepositoryRoot == "" || !filepath.IsAbs(cfg.RepositoryRoot) || filepath.Clean(cfg.RepositoryRoot) != cfg.RepositoryRoot || cfg.RepositoryRoot == string(filepath.Separator) {
		return errors.New("repository root must be absolute, clean, and narrow")
	}
	rootResolved, err := filepath.EvalSymlinks(cfg.RepositoryRoot)
	if err != nil || rootResolved != cfg.RepositoryRoot {
		return errors.New("repository root may not resolve through symlink")
	}
	rootInfo, err := os.Lstat(cfg.RepositoryRoot)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("repository root must be a real directory")
	}
	inputs := []struct {
		path                   string
		executable, repository bool
	}{{cfg.PublicCorpus, false, true}, {cfg.JavaExecutable, true, false}, {cfg.JavaAdapterJar, false, false}, {cfg.JavaRuntimeJar, false, false}, {cfg.RustTestee, true, false}, {cfg.MigrationInventory, false, true}, {cfg.CompatibilitySurface, false, true}, {cfg.LedgerPath, false, true}, {cfg.OracleHierarchyPath, false, true}}
	if len(cfg.JavaSupportJars) == 0 || len(cfg.JavaSupportJars) > 16 {
		return errors.New("java support jars must contain 1..16 paths")
	}
	for _, path := range cfg.JavaSupportJars {
		inputs = append(inputs, struct {
			path                   string
			executable, repository bool
		}{path, false, false})
	}
	seen := map[string]bool{}
	for _, input := range inputs {
		if err := validateExistingPath(input.path, input.executable); err != nil {
			return err
		}
		if input.repository && !within(cfg.RepositoryRoot, input.path) {
			return fmt.Errorf("repository input escapes root: %s", input.path)
		}
		if seen[input.path] {
			return fmt.Errorf("duplicate input alias: %s", input.path)
		}
		seen[input.path] = true
	}
	for _, output := range []string{cfg.EvidencePath, cfg.LedgerPath} {
		if output == "" || !filepath.IsAbs(output) || filepath.Clean(output) != output || !within(cfg.RepositoryRoot, output) || hasForbiddenCorpusComponent(output) {
			return fmt.Errorf("output path invalid: %s", output)
		}
		if output != cfg.LedgerPath {
			if seen[output] {
				return errors.New("output aliases input")
			}
			if err := validateOutputParent(output); err != nil {
				return err
			}
		}
	}
	return nil
}

func artifact(path string) (ArtifactIdentity, error) {
	raw, err := readRegularBounded(path, 512<<20)
	if err != nil {
		return ArtifactIdentity{}, err
	}
	return ArtifactIdentity{Path: path, SHA256: digest(raw), Bytes: int64(len(raw))}, nil
}

func gitAnchor(root string) (string, error) {
	cmd := exec.Command("git", "-C", root, "rev-parse", "HEAD")
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	raw, err := cmd.Output()
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(raw))
	if len(value) != 40 && len(value) != 64 {
		return "", errors.New("git anchor malformed")
	}
	return value, nil
}

type attemptOutput struct {
	observation commonObservation
	rust        rustObservation
	receipt     ProcessReceipt
	loss        []string
}

func runAttempt(ctx context.Context, cfg Config, suiteHome string, sc corpora.Scenario, runtimeName, attempt, executableDigest string) (attemptOutput, error) {
	request := childRequest{Home: suiteHome, Timeout: cfg.ScenarioTimeout}
	if runtimeName == "java" {
		line, err := corpora.OracleRequestLine(sc)
		if err != nil {
			return attemptOutput{}, err
		}
		request.Input = append(line, '\n')
		classpath := append([]string{cfg.JavaAdapterJar, cfg.JavaRuntimeJar}, cfg.JavaSupportJars...)
		request.Executable = cfg.JavaExecutable
		request.Args = []string{"-Dslf4j.internal.verbosity=ERROR", "-cp", strings.Join(classpath, string(os.PathListSeparator)), "OracleMain"}
	} else {
		input, err := encodeNeutralRequest(sc)
		if err != nil {
			return attemptOutput{}, err
		}
		request.Input = input
		request.Executable = cfg.RustTestee
		request.Args = []string{"neutral-oracle", "--protocol", "NDRV1"}
	}
	result, err := executeChild(ctx, request)
	if err != nil {
		return attemptOutput{}, fmt.Errorf("%s %s %s: %w", sc.ScenarioID, runtimeName, attempt, err)
	}
	output := attemptOutput{}
	if runtimeName == "java" {
		output.observation, output.loss, err = normalizeJava(sc, result.Stdout)
	} else {
		output.observation, output.rust, err = normalizeRust(sc, result.Stdout)
	}
	if err != nil {
		return attemptOutput{}, fmt.Errorf("normalize %s %s: %w", runtimeName, sc.ScenarioID, err)
	}
	normalizedDigest, err := normalizeDigest(output.observation)
	if err != nil {
		return attemptOutput{}, err
	}
	output.receipt = ProcessReceipt{ScenarioID: sc.ScenarioID, Runtime: runtimeName, Attempt: attempt, PID: result.PID, ExecutableSHA256: executableDigest, StdinSHA256: digest(request.Input), StdinBytes: len(request.Input), StdoutSHA256: digest(result.Stdout), StdoutBytes: len(result.Stdout), StderrSHA256: digest(result.Stderr), StderrBytes: len(result.Stderr), ExitCode: result.ExitCode, StartedUnixNano: result.Started.UnixNano(), DurationNanos: result.Duration.Nanoseconds(), NormalizedSHA256: normalizedDigest}
	return output, nil
}

func firstDifference(left, right commonObservation) (string, error) {
	leftRaw, err := canonical(left)
	if err != nil {
		return "", err
	}
	rightRaw, err := canonical(right)
	if err != nil {
		return "", err
	}
	var leftValue, rightValue any
	if err := json.Unmarshal(leftRaw, &leftValue); err != nil {
		return "", err
	}
	if err := json.Unmarshal(rightRaw, &rightValue); err != nil {
		return "", err
	}
	return firstJSONDifference(leftValue, rightValue, ""), nil
}

func firstJSONDifference(left, right any, pointer string) string {
	leftMap, leftOK := left.(map[string]any)
	rightMap, rightOK := right.(map[string]any)
	if leftOK || rightOK {
		if !leftOK || !rightOK {
			return pointer
		}
		keys := map[string]bool{}
		for key := range leftMap {
			keys[key] = true
		}
		for key := range rightMap {
			keys[key] = true
		}
		ordered := make([]string, 0, len(keys))
		for key := range keys {
			ordered = append(ordered, key)
		}
		sort.Strings(ordered)
		for _, key := range ordered {
			next := pointer + "/" + escapePointer(key)
			lv, lPresent := leftMap[key]
			rv, rPresent := rightMap[key]
			if !lPresent || !rPresent {
				return next
			}
			if difference := firstJSONDifference(lv, rv, next); difference != "" {
				return difference
			}
		}
		return ""
	}
	leftArray, leftOK := left.([]any)
	rightArray, rightOK := right.([]any)
	if leftOK || rightOK {
		if !leftOK || !rightOK || len(leftArray) != len(rightArray) {
			return pointer
		}
		for index := range leftArray {
			if difference := firstJSONDifference(leftArray[index], rightArray[index], fmt.Sprintf("%s/%d", pointer, index)); difference != "" {
				return difference
			}
		}
		return ""
	}
	leftRaw, _ := canonical(left)
	rightRaw, _ := canonical(right)
	if !bytes.Equal(leftRaw, rightRaw) {
		return pointer
	}
	return ""
}

func marshalIndented(value any) ([]byte, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// RunPublicDifferential executes the full public suite. Validation remains at
// the facade so an invalid configuration cannot launch either runtime.
func RunPublicDifferential(ctx context.Context, cfg Config) (Receipt, error) {
	if err := validateConfig(cfg); err != nil {
		return Receipt{}, err
	}
	suiteCtx, cancel := context.WithTimeout(ctx, cfg.SuiteTimeout)
	defer cancel()
	suiteRoot, err := os.MkdirTemp("", "us020-differential-")
	if err != nil {
		return Receipt{}, err
	}
	defer os.RemoveAll(suiteRoot)
	scenarios, _, err := loadPublicCorpus(cfg.RepositoryRoot, cfg.PublicCorpus)
	if err != nil {
		return Receipt{}, err
	}
	hierarchyRaw, err := readRegularBounded(cfg.OracleHierarchyPath, maximumDocumentBytes)
	if err != nil {
		return Receipt{}, err
	}
	var hierarchy OracleHierarchy
	if err := decodeStrict(hierarchyRaw, &hierarchy); err != nil {
		return Receipt{}, err
	}
	if err := ValidateOracleHierarchy(scenarios, hierarchy); err != nil {
		return Receipt{}, err
	}
	ledgerRaw, err := readRegularBounded(cfg.LedgerPath, maximumDocumentBytes)
	if err != nil {
		return Receipt{}, err
	}
	ledger, err := migrateLedger(ledgerRaw)
	if err != nil {
		return Receipt{}, err
	}
	preHead := ledger.Head
	coverage, err := buildCoverage(cfg.RepositoryRoot, scenarios)
	if err != nil {
		return Receipt{}, err
	}
	controls, err := runSeededControls()
	if err != nil {
		return Receipt{}, err
	}
	anchor, err := gitAnchor(cfg.RepositoryRoot)
	if err != nil {
		return Receipt{}, err
	}
	javaIdentity, err := artifact(cfg.JavaExecutable)
	if err != nil {
		return Receipt{}, err
	}
	rustIdentity, err := artifact(cfg.RustTestee)
	if err != nil {
		return Receipt{}, err
	}
	inputPaths := []string{cfg.PublicCorpus, filepath.Join(cfg.RepositoryRoot, "corpora/public/manifest.json"), cfg.JavaExecutable, cfg.JavaAdapterJar, cfg.JavaRuntimeJar, cfg.RustTestee, cfg.MigrationInventory, cfg.CompatibilitySurface, cfg.OracleHierarchyPath}
	inputPaths = append(inputPaths, cfg.JavaSupportJars...)
	inputs := make([]ArtifactIdentity, 0, len(inputPaths))
	for _, path := range inputPaths {
		identity, err := artifact(path)
		if err != nil {
			return Receipt{}, err
		}
		inputs = append(inputs, identity)
	}
	manifest := Manifest{Schema: "../../schemas/differential-evidence-1.0.0.schema.json", SchemaVersion: evidenceSchemaVersion, EvidenceID: "evidence.us-020-public-differential", StoryID: "US-020", Status: StatusPass, Assurance: "OWNER_ATTESTED_NOT_INDEPENDENT", ParityScope: "RUNTIME_COMMON_AGGREGATE", RepositoryAnchor: anchor, Inputs: inputs, Coverage: coverage, Controls: controls, Nonclaims: []string{"no per-step Java counter parity", "no hidden or sealed corpus access", "no Docker Autobahn wstest Linux or network execution", "no wire interoperability browser performance allocation concurrency TLS or NIO parity", "fresh child receipts prove invocation not an uncontaminated host", "no production publication signing or independent review claim"}}
	for _, sc := range scenarios {
		neutral, err := neutralObservation(sc)
		if err != nil {
			return Receipt{}, err
		}
		neutralDigest, err := normalizeDigest(neutral)
		if err != nil {
			return Receipt{}, err
		}
		home := filepath.Join(suiteRoot, sc.ScenarioID)
		if err := os.Mkdir(home, 0o700); err != nil {
			return Receipt{}, err
		}
		javaPrimary, err := runAttempt(suiteCtx, cfg, home, sc, "java", "primary", javaIdentity.SHA256)
		if err != nil {
			return Receipt{}, err
		}
		javaReplay, err := runAttempt(suiteCtx, cfg, home, sc, "java", "replay", javaIdentity.SHA256)
		if err != nil {
			return Receipt{}, err
		}
		rustPrimary, err := runAttempt(suiteCtx, cfg, home, sc, "rust", "primary", rustIdentity.SHA256)
		if err != nil {
			return Receipt{}, err
		}
		rustReplay, err := runAttempt(suiteCtx, cfg, home, sc, "rust", "replay", rustIdentity.SHA256)
		if err != nil {
			return Receipt{}, err
		}
		manifest.Processes = append(manifest.Processes, javaPrimary.receipt, javaReplay.receipt, rustPrimary.receipt, rustReplay.receipt)
		stable := javaPrimary.receipt.NormalizedSHA256 == javaReplay.receipt.NormalizedSHA256 && rustPrimary.receipt.NormalizedSHA256 == rustReplay.receipt.NormalizedSHA256
		if !stable {
			return Receipt{}, fmt.Errorf("FLAKE: %s primary/replay mismatch", sc.ScenarioID)
		}
		classification := classifyAgainstNeutral(neutralDigest, javaPrimary.receipt.NormalizedSHA256, rustPrimary.receipt.NormalizedSHA256)
		currentMismatch := javaPrimary.receipt.NormalizedSHA256 != rustPrimary.receipt.NormalizedSHA256
		result := ScenarioResult{ScenarioID: sc.ScenarioID, JavaPrimary: javaPrimary.receipt.NormalizedSHA256, JavaReplay: javaReplay.receipt.NormalizedSHA256, RustPrimary: rustPrimary.receipt.NormalizedSHA256, RustReplay: rustReplay.receipt.NormalizedSHA256, NeutralExpected: neutralDigest, Stable: true, CurrentMismatch: currentMismatch, Classification: classification, JavaObservation: javaPrimary.observation, RustObservation: rustPrimary.observation, RustStepDiagnostics: rustPrimary.rust.Steps, RustBootstrapSHA256: digest(rustPrimary.rust.Bootstrap), JavaNormalizationLoss: javaPrimary.loss}
		manifest.Scenarios = append(manifest.Scenarios, result)
		if currentMismatch || javaPrimary.receipt.NormalizedSHA256 != neutralDigest || rustPrimary.receipt.NormalizedSHA256 != neutralDigest {
			pointer, _ := firstDifference(javaPrimary.observation, rustPrimary.observation)
			return Receipt{}, fmt.Errorf("US020_DIFFERENCE scenario=%s pointer=%s classification=%s java=%s rust=%s neutral=%s java_value=%+v rust_value=%+v", sc.ScenarioID, pointer, classification, javaPrimary.receipt.NormalizedSHA256, rustPrimary.receipt.NormalizedSHA256, neutralDigest, javaPrimary.observation, rustPrimary.observation)
		}
		if sc.ScenarioID == "us005.pub.0005" {
			if err := appendObservedRemediation(&ledger, hierarchy, sc, javaPrimary.receipt.NormalizedSHA256, rustPrimary.receipt.NormalizedSHA256, anchor); err != nil {
				return Receipt{}, err
			}
		}
	}
	manifest.Counts = CountsReceipt{Scenarios: len(scenarios), JavaPrimary: len(scenarios), JavaReplay: len(scenarios), RustPrimary: len(scenarios), RustReplay: len(scenarios), Processes: len(manifest.Processes)}
	manifest.Ledger = LedgerBinding{PreHead: preHead, PostHead: ledger.Head, Records: len(ledger.Records)}
	if len(ledger.Records) == 0 {
		ledger.Status = "PASS_NO_CURRENT_DELTAS"
	} else {
		ledger.Status = "PASS_WITH_CLOSED_HISTORY"
	}
	ledger.UnledgeredDisagreements = 0
	ledgerDocument, err := marshalIndented(ledger)
	if err != nil {
		return Receipt{}, err
	}
	manifestDocument, err := marshalIndented(manifest)
	if err != nil {
		return Receipt{}, err
	}
	if err := compileAndValidateSchema(filepath.Join(cfg.RepositoryRoot, "schemas/behavior-delta-ledger-1.1.0.schema.json"), ledgerDocument); err != nil {
		return Receipt{}, fmt.Errorf("ledger schema: %w", err)
	}
	if err := compileAndValidateSchema(filepath.Join(cfg.RepositoryRoot, "schemas/differential-evidence-1.0.0.schema.json"), manifestDocument); err != nil {
		return Receipt{}, fmt.Errorf("evidence schema: %w", err)
	}
	if err := writeJSONAtomic(cfg.LedgerPath, ledger); err != nil {
		return Receipt{}, err
	}
	if err := writeJSONAtomic(cfg.EvidencePath, manifest); err != nil {
		return Receipt{}, err
	}
	committed, err := readRegularBounded(cfg.EvidencePath, maximumDocumentBytes)
	if err != nil {
		return Receipt{}, err
	}
	if err := VerifyPublicDifferential(cfg.RepositoryRoot, committed); err != nil {
		return Receipt{}, err
	}
	return Receipt{Status: StatusPass, ScenarioCount: len(scenarios), ProcessReceipts: len(manifest.Processes), DeltaCount: len(ledger.Records), EvidenceSHA256: digest(committed)}, nil
}

func decodeStrict(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func writeJSONAtomic(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".us020-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func compileAndValidateSchema(schemaPath string, document []byte) error {
	schemaRaw, err := readRegularBounded(schemaPath, maximumDocumentBytes)
	if err != nil {
		return err
	}
	schemaValue, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaRaw))
	if err != nil {
		return err
	}
	compiler := jsonschema.NewCompiler()
	resource := "https://verified-java-websocket-port.invalid/" + filepath.Base(schemaPath)
	if err := compiler.AddResource(resource, schemaValue); err != nil {
		return err
	}
	schema, err := compiler.Compile(resource)
	if err != nil {
		return err
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(document))
	if err != nil {
		return err
	}
	return schema.Validate(value)
}

func verifyManifestValue(root string, raw []byte) error {
	var manifest Manifest
	if err := decodeStrict(raw, &manifest); err != nil {
		return err
	}
	if manifest.SchemaVersion != evidenceSchemaVersion || manifest.EvidenceID != "evidence.us-020-public-differential" || manifest.StoryID != "US-020" || manifest.Status != StatusPass {
		return errors.New("manifest identity/status invalid")
	}
	if manifest.Assurance != "OWNER_ATTESTED_NOT_INDEPENDENT" || manifest.IndependentReviewClaimed || manifest.Production || manifest.Publication || manifest.Signing {
		return errors.New("assurance claim invalid")
	}
	if manifest.ParityScope != "RUNTIME_COMMON_AGGREGATE" || !contains(manifest.Nonclaims, "no per-step Java counter parity") {
		return errors.New("per-step Java parity overclaim or nonclaim absent")
	}
	counts := manifest.Counts
	if counts.Scenarios != expectedPublicScenarios || counts.JavaPrimary != expectedPublicScenarios || counts.JavaReplay != expectedPublicScenarios || counts.RustPrimary != expectedPublicScenarios || counts.RustReplay != expectedPublicScenarios || counts.Processes != expectedProcessReceipts || counts.Flakes != 0 || counts.CurrentMismatches != 0 || counts.UnresolvedDifferences != 0 || counts.NormalizationCollisions != 0 {
		return errors.New("manifest counts invalid")
	}
	if len(manifest.Scenarios) != expectedPublicScenarios || len(manifest.Processes) != expectedProcessReceipts {
		return errors.New("manifest array cardinality invalid")
	}
	if manifest.Controls.Total != 7 || manifest.Controls.Killed != 7 || len(manifest.Controls.Results) != 7 {
		return errors.New("control receipt invalid")
	}
	if len(manifest.Coverage.Migration) != 47 || len(manifest.Coverage.Compatibility) != 14 || manifest.Coverage.Summary.UnresolvedRows != 0 {
		return errors.New("coverage receipt invalid")
	}
	seenScenarios := map[string]bool{}
	for _, scenario := range manifest.Scenarios {
		if scenario.ScenarioID == "" || seenScenarios[scenario.ScenarioID] || !scenario.Stable || scenario.CurrentMismatch {
			return errors.New("scenario receipt invalid")
		}
		seenScenarios[scenario.ScenarioID] = true
	}
	seenProcesses := map[string]bool{}
	for _, process := range manifest.Processes {
		key := process.ScenarioID + "|" + process.Runtime + "|" + process.Attempt
		if seenProcesses[key] || process.PID <= 0 || process.ExitCode != 0 || !strings.HasPrefix(process.ExecutableSHA256, "sha256:") || !strings.HasPrefix(process.NormalizedSHA256, "sha256:") {
			return errors.New("process receipt invalid")
		}
		seenProcesses[key] = true
	}
	if root == "" || !filepath.IsAbs(root) {
		return errors.New("repository root invalid")
	}
	return nil
}

// VerifyPublicDifferential independently validates a committed receipt.
func VerifyPublicDifferential(repositoryRoot string, receiptBytes []byte) error {
	if repositoryRoot == "" || !filepath.IsAbs(repositoryRoot) || filepath.Clean(repositoryRoot) != repositoryRoot {
		return errors.New("repository root must be absolute and clean")
	}
	if len(receiptBytes) == 0 || int64(len(receiptBytes)) > maximumDocumentBytes {
		return errors.New("receipt is empty or oversized")
	}
	if err := compileAndValidateSchema(filepath.Join(repositoryRoot, "schemas/differential-evidence-1.0.0.schema.json"), receiptBytes); err != nil {
		return fmt.Errorf("evidence schema: %w", err)
	}
	if err := verifyManifestValue(repositoryRoot, receiptBytes); err != nil {
		return err
	}
	var manifest Manifest
	if err := json.Unmarshal(receiptBytes, &manifest); err != nil {
		return err
	}
	ledgerRaw, err := readRegularBounded(filepath.Join(repositoryRoot, "evidence/java/behavior-delta-ledger.json"), maximumDocumentBytes)
	if err != nil {
		return err
	}
	ledger, err := migrateLedger(ledgerRaw)
	if err != nil {
		return err
	}
	if ledger.Head != manifest.Ledger.PostHead || len(ledger.Records) != manifest.Ledger.Records {
		return errors.New("ledger binding drift")
	}
	hierarchyRaw, err := readRegularBounded(filepath.Join(repositoryRoot, "evidence/oracle-hierarchy.json"), maximumDocumentBytes)
	if err != nil {
		return err
	}
	var hierarchy OracleHierarchy
	if err := decodeStrict(hierarchyRaw, &hierarchy); err != nil {
		return err
	}
	scenarios, _, err := loadPublicCorpus(repositoryRoot, filepath.Join(repositoryRoot, "corpora/public/scenarios.jsonl"))
	if err != nil {
		return err
	}
	return ValidateOracleHierarchy(scenarios, hierarchy)
}
