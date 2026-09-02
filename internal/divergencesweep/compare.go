package divergencesweep

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Every key an Autobahn per-case report carries is placed in exactly one of
// three groups, and the sweep refuses a report whose key set is not exactly
// their union. A field that appears in a future run without being classified
// is a hole in the comparison, so it is an error rather than a silent skip.

// InvariantFields must be byte-equal between the two subjects. They describe
// the CASE, not the subject: if they differ the two legs did not walk the same
// manifest and no comparison below is meaningful.
var InvariantFields = []string{
	"case",
	"createStats",
	"createWirelog",
	"description",
	"expectation",
	"expected",
	"expectedClose",
	"id",
	"isServer",
	"reportCompressionRatio",
	"reportTime",
	"trafficStats",
}

// NotComparableFields are recorded with the reason they cannot be compared
// verbatim. Derived dimensions recover the comparable part of the two
// handshake fields; nothing is recovered from the other four.
var NotComparableFields = []struct {
	Field  string
	Reason string
}{
	{"agent", "the agent name identifies which subject produced the leg, so it differs by construction"},
	{"duration", "wall-clock milliseconds on a shared host"},
	{"httpRequest", "carries a per-connection random Sec-WebSocket-Key, the harness-assigned agent name and, on the Java legs, the fixed Host authority the endpoint pins (RUN-NOTES deviation 3); the comparable part is recovered as the subject_handshake_* and suite_handshake_* dimensions"},
	{"httpResponse", "carries the Sec-WebSocket-Accept derived from that random key; the comparable part is recovered as the subject_handshake_* and suite_handshake_* dimensions"},
	{"rxOctetStats", "a histogram of the sizes of the chunks the suite READ off the socket, which is TCP segmentation and scheduling, not a subject-observable protocol behaviour; the protocol-level part is carried by rx_frame_stats and by the handshake dimensions"},
	{"started", "absolute start timestamp"},
	{"txOctetStats", "a histogram of the sizes of the chunks the suite WROTE, which is likewise segmentation; the suite's own writes are the same frames on both legs, which rx_frame_stats and tx_frame_stats do compare"},
	{"wirelog", "every masked frame carries a per-frame random mask key, and the handshake octets carry the random key above"},
}

// Dimension is one comparison the sweep makes per case.
type Dimension struct {
	// Name is the dimension's name in the emitted document.
	Name string
	// Field is the report key it reads, or "" for a derived dimension.
	Field string
	// Group is the question the dimension belongs to: "close" (the close
	// code, the close reason and who ended the TCP connection), "protocol"
	// (what the subject did with the frames) or "handshake" (the opening
	// handshake head the subject wrote).
	Group string
	// What the dimension observes, in one line.
	Meaning string
	// Derive computes the compared value. A nil Derive reads Field verbatim.
	Derive func(leg *Leg, report map[string]any) (any, error)
}

// ComparedFields is the set of report keys read verbatim by a dimension.
func ComparedFields() []string {
	seen := map[string]bool{}
	var fields []string
	for _, dimension := range Dimensions() {
		if dimension.Field == "" || seen[dimension.Field] {
			continue
		}
		seen[dimension.Field] = true
		fields = append(fields, dimension.Field)
	}
	sort.Strings(fields)
	return fields
}

// Dimensions is the closed, ordered set of comparisons. The first block is the
// close question this sweep exists for; the rest is everything else the report
// bytes make comparable, so that "we found nothing there" is a measurement and
// not an omission.
func Dimensions() []Dimension {
	return []Dimension{
		// --- close code, close reason, who closed TCP -------------------
		{
			Name:    "subject_close_code",
			Group:   "close",
			Field:   "remoteCloseCode",
			Meaning: "the close code the SUBJECT sent; null when the subject sent no close frame at all",
		},
		{
			Name:    "subject_close_reason",
			Group:   "close",
			Field:   "remoteCloseReason",
			Meaning: "the close reason string the SUBJECT sent",
		},
		{
			Name:    "tcp_connection_dropped_by",
			Group:   "close",
			Meaning: "which peer dropped the TCP connection, named from the suite's droppedByMe flag",
			Derive: func(_ *Leg, report map[string]any) (any, error) {
				dropped, ok := report["droppedByMe"].(bool)
				if !ok {
					return nil, fmt.Errorf("droppedByMe is not a boolean")
				}
				if dropped {
					return "AUTOBAHN_SUITE", nil
				}
				return "SUBJECT", nil
			},
		},
		{
			Name:    "suite_dropped_tcp",
			Group:   "close",
			Field:   "droppedByMe",
			Meaning: "raw flag behind tcp_connection_dropped_by: the suite dropped the TCP connection",
		},
		{
			Name:    "close_handshake_initiated_by_suite",
			Group:   "close",
			Field:   "closedByMe",
			Meaning: "the suite sent the first close frame",
		},
		{
			Name:    "suite_close_code",
			Group:   "close",
			Field:   "localCloseCode",
			Meaning: "the close code the SUITE sent, which the subject's behaviour drives",
		},
		{
			Name:    "suite_close_reason",
			Group:   "close",
			Field:   "localCloseReason",
			Meaning: "the close reason string the SUITE sent",
		},
		{
			Name:    "close_was_clean",
			Group:   "close",
			Field:   "wasClean",
			Meaning: "the suite scored the close handshake clean",
		},
		{
			Name:    "not_clean_reason",
			Group:   "close",
			Field:   "wasNotCleanReason",
			Meaning: "the suite's stated reason the close was not clean",
		},
		{
			Name:    "close_handshake_timeout",
			Group:   "close",
			Field:   "wasCloseHandshakeTimeout",
			Meaning: "the subject never answered the suite's close frame in time",
		},
		{
			Name:    "server_connection_drop_timeout",
			Group:   "close",
			Field:   "wasServerConnectionDropTimeout",
			Meaning: "the subject, as server, never dropped the TCP connection in time",
		},
		{
			Name:    "open_handshake_timeout",
			Group:   "close",
			Field:   "wasOpenHandshakeTimeout",
			Meaning: "the opening handshake never completed in time",
		},
		{
			Name:    "failed_by_suite",
			Group:   "close",
			Field:   "failedByMe",
			Meaning: "the suite failed the connection",
		},
		{
			Name:    "close_verdict_text",
			Group:   "close",
			Field:   "resultClose",
			Meaning: "the suite's free-text verdict on the close",
		},
		// --- everything else the reports make comparable ------------------
		{
			Name:    "behavior",
			Group:   "protocol",
			Field:   "behavior",
			Meaning: "the Autobahn behaviour class, recomputed here so the sweep is bound to the class the comparison document records",
		},
		{
			Name:    "behavior_close",
			Group:   "protocol",
			Field:   "behaviorClose",
			Meaning: "the Autobahn close behaviour class, recomputed for the same reason",
		},
		{
			Name:    "behavior_verdict_text",
			Group:   "protocol",
			Field:   "result",
			Meaning: "the suite's free-text verdict on the behaviour",
		},
		{
			Name:    "received_messages",
			Group:   "protocol",
			Field:   "received",
			Meaning: "the messages the suite received from the subject",
		},
		{
			Name:    "rx_frame_stats",
			Group:   "protocol",
			Field:   "rxFrameStats",
			Meaning: "frames the suite received from the subject, by opcode",
		},
		{
			Name:    "tx_frame_stats",
			Group:   "protocol",
			Field:   "txFrameStats",
			Meaning: "frames the suite sent to the subject, by opcode",
		},
		{
			Name:    "subject_handshake_header_names",
			Group:   "handshake",
			Meaning: "the sequence of header names the SUBJECT wrote in the opening handshake, in the order it wrote them",
			Derive: func(leg *Leg, report map[string]any) (any, error) {
				return handshakeHeaderNames(report, subjectHandshakeField(leg))
			},
		},
		{
			Name:    "subject_handshake_start_line",
			Group:   "handshake",
			Meaning: "the SUBJECT's HTTP start line, with the harness-assigned agent name redacted",
			Derive: func(leg *Leg, report map[string]any) (any, error) {
				return handshakeStartLine(report, subjectHandshakeField(leg))
			},
		},
		{
			Name:    "suite_handshake_header_names",
			Group:   "handshake",
			Meaning: "the same for the SUITE's side; a difference here would mean the two legs were not driven alike",
			Derive: func(leg *Leg, report map[string]any) (any, error) {
				return handshakeHeaderNames(report, suiteHandshakeField(leg))
			},
		},
		{
			Name:    "suite_handshake_start_line",
			Group:   "handshake",
			Meaning: "the SUITE's HTTP start line, with the harness-assigned agent name redacted",
			Derive: func(leg *Leg, report map[string]any) (any, error) {
				return handshakeStartLine(report, suiteHandshakeField(leg))
			},
		},
	}
}

func subjectHandshakeField(leg *Leg) string {
	if leg.Spec.SubjectRole == "server" {
		return "httpResponse"
	}
	return "httpRequest"
}

func suiteHandshakeField(leg *Leg) string {
	if leg.Spec.SubjectRole == "server" {
		return "httpRequest"
	}
	return "httpResponse"
}

func handshakeLines(report map[string]any, field string) ([]string, error) {
	raw, ok := report[field].(string)
	if !ok {
		return nil, fmt.Errorf("%s is not a string", field)
	}
	return strings.Split(raw, "\r\n"), nil
}

func handshakeHeaderNames(report map[string]any, field string) (any, error) {
	lines, err := handshakeLines(report, field)
	if err != nil {
		return nil, err
	}
	names := []any{}
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		name, _, found := strings.Cut(line, ":")
		if !found {
			return nil, fmt.Errorf("%s: header line %q has no colon", field, line)
		}
		names = append(names, name)
	}
	return names, nil
}

// handshakeStartLine redacts the agent name the harness assigns each subject.
// The Autobahn client leg puts it in the request target (…&agent=<name>), so
// without this the start line would differ by construction and say nothing.
// Nothing else in the start line is touched.
func handshakeStartLine(report map[string]any, field string) (any, error) {
	lines, err := handshakeLines(report, field)
	if err != nil {
		return nil, err
	}
	start := lines[0]
	const marker = "agent="
	index := strings.Index(start, marker)
	if index < 0 {
		return start, nil
	}
	tail := start[index+len(marker):]
	end := strings.IndexAny(tail, "& ")
	if end < 0 {
		return start[:index+len(marker)] + "<agent>", nil
	}
	return start[:index+len(marker)] + "<agent>" + tail[end:], nil
}

// Verdict is the per-case outcome of one dimension.
type Verdict string

const (
	// VerdictAgree means the two subjects produced the same value.
	VerdictAgree Verdict = "AGREE"
	// VerdictPortAbsent means the port produced no value (JSON null or the
	// key absent) where Java produced one.
	VerdictPortAbsent Verdict = "PORT_ABSENT_JAVA_PRESENT"
	// VerdictJavaAbsent is the mirror.
	VerdictJavaAbsent Verdict = "JAVA_ABSENT_PORT_PRESENT"
	// VerdictBothDiffer means both produced a value and they are different.
	VerdictBothDiffer Verdict = "BOTH_PRESENT_DIFFER"
)

// Verdicts is the closed set, in the order the document reports them.
func Verdicts() []Verdict {
	return []Verdict{VerdictAgree, VerdictPortAbsent, VerdictJavaAbsent, VerdictBothDiffer}
}

func classify(port, java any) Verdict {
	portJSON := canonical(port)
	javaJSON := canonical(java)
	if portJSON == javaJSON {
		return VerdictAgree
	}
	if port == nil {
		return VerdictPortAbsent
	}
	if java == nil {
		return VerdictJavaAbsent
	}
	return VerdictBothDiffer
}

func canonical(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("<unencodable:%v>", err)
	}
	return string(encoded)
}

// renderValueLimit bounds how much of a value the document quotes. A value
// longer than this is quoted up to the limit and identified by the digest of
// its full canonical encoding, so a large payload is still distinguishable
// without the document swallowing it.
const renderValueLimit = 220

func render(value any) string {
	encoded := canonical(value)
	if len(encoded) <= renderValueLimit {
		return encoded
	}
	sum := sha256.Sum256([]byte(encoded))
	return encoded[:renderValueLimit] + fmt.Sprintf("…<truncated, %d bytes, sha256:%s>",
		len(encoded), hex.EncodeToString(sum[:]))
}
