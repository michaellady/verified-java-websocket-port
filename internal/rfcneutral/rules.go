package rfcneutral

import "sort"

// Rule is one stated rule of RFC 6455, transcribed once and applied uniformly.
//
// The transcription is a recorded reading: the RFC text is not in this
// repository (see the package doc), so Clauses is what a reader with the text
// checks this table against. Quote is the sentence this reading rests on,
// recorded so that a wrong reading is visible as a wrong quote rather than
// hidden in code.
type Rule struct {
	// ID is stable and appears in every decision the rule decides.
	ID string `json:"id"`
	// Clauses are the RFC 6455 sections the rule is read out of.
	Clauses []string `json:"rfc_clauses"`
	// Quote is the reading of the clause this rule encodes.
	Quote string `json:"reading"`
	// Effect is the ready-state consequence: "closed" for the rules that
	// require Failing the WebSocket Connection, "open" for the terminal
	// no-violation rule, and "" for the rules that abstain.
	Effect string `json:"effect"`
}

// The ready-state verdict space of the public tier. The corpus also carries
// "closing"; this derivation never emits it, because RFC 6455 does not define
// readyState and cannot distinguish a closing handshake in progress from a
// closed connection without the transport state. See RuleClosingHandshake.
const (
	VerdictOpen   = "open"
	VerdictClosed = "closed"
)

// Rule identities. Deciding rules first, then abstaining rules.
const (
	RuleUnmaskedToServer   = "R-5.1-unmasked-frame-to-server"
	RuleMaskedToClient     = "R-5.1-masked-frame-to-client"
	RuleReservedBit        = "R-5.2-nonzero-rsv-without-extension"
	RuleReservedOpcode     = "R-5.2-reserved-opcode"
	RuleNonMinimalLength   = "R-5.2-non-minimal-length-encoding"
	RuleLength64HighBit    = "R-5.2-64-bit-length-high-bit-set"
	RuleControlOversize    = "R-5.5-control-frame-over-125-octets"
	RuleControlFragmented  = "R-5.5-fragmented-control-frame"
	RuleOrphanContinuation = "R-5.4-continuation-without-a-fragmented-message"
	RuleInterleavedData    = "R-5.4-data-frame-inside-a-fragmented-message"
	RuleCloseBodyLength1   = "R-5.5.1-close-body-of-exactly-one-octet"
	RuleCloseCodeInvalid   = "R-7.4-close-status-code-not-defined-for-the-wire"
	RuleCloseReasonNotUTF8 = "R-5.5.1-close-reason-not-valid-utf8"
	RuleTextNotUTF8        = "R-5.6-text-payload-not-valid-utf8"
	RuleNoViolation        = "R-terminal-no-provision-required-failing"
)

// Abstaining rules. Each names a question RFC 6455 sections 5 and 7 do not
// answer, so this derivation declines rather than inventing one.
const (
	AbstainNonOpenInitialState = "A-readystate-not-defined-by-rfc6455-non-open-initial-state"
	AbstainClosingHandshake    = "A-readystate-not-defined-by-rfc6455-closing-handshake-started"
	AbstainLocalAPIAction      = "A-no-provision-governs-a-local-application-send"
	AbstainHarnessLimit        = "A-harness-limit-not-stated-by-rfc6455"
	AbstainTruncatedTrailer    = "A-frame-header-truncated-mid-stream"
)

// rules is the whole table, in the order the decoder consults it per frame.
var rules = []Rule{
	{
		ID:      RuleUnmaskedToServer,
		Clauses: []string{"rfc6455#section-5.1"},
		Quote:   "A client MUST mask all frames that it sends to the server. A server MUST close the connection upon receiving a frame that is not masked.",
		Effect:  VerdictClosed,
	},
	{
		ID:      RuleMaskedToClient,
		Clauses: []string{"rfc6455#section-5.1"},
		Quote:   "A server MUST NOT mask any frames that it sends to the client. A client MUST close a connection if it detects a masked frame.",
		Effect:  VerdictClosed,
	},
	{
		ID:      RuleReservedBit,
		Clauses: []string{"rfc6455#section-5.2", "rfc6455#section-7.1.7"},
		Quote:   "RSV1, RSV2, RSV3: MUST be 0 unless an extension is negotiated that defines meanings for non-zero values. If a nonzero value is received and none of the negotiated extensions defines the meaning of such a nonzero value, the receiving endpoint MUST Fail the WebSocket Connection. No extension is negotiated anywhere in this corpus.",
		Effect:  VerdictClosed,
	},
	{
		ID:      RuleReservedOpcode,
		Clauses: []string{"rfc6455#section-5.2", "rfc6455#section-7.1.7"},
		Quote:   "Opcodes %x3-7 and %xB-F are reserved for further frames. If an unknown opcode is received, the receiving endpoint MUST Fail the WebSocket Connection.",
		Effect:  VerdictClosed,
	},
	{
		ID:      RuleNonMinimalLength,
		Clauses: []string{"rfc6455#section-5.2", "rfc6455#section-7.1.7"},
		Quote:   "Payload length: ... if 126, the following 2 bytes interpreted as a 16-bit unsigned integer are the payload length; if 127, the following 8 bytes ... The minimal number of bytes MUST be used to encode the length.",
		Effect:  VerdictClosed,
	},
	{
		ID:      RuleLength64HighBit,
		Clauses: []string{"rfc6455#section-5.2", "rfc6455#section-7.1.7"},
		Quote:   "the following 8 bytes interpreted as a 64-bit unsigned integer (the most significant bit MUST be 0) are the payload length.",
		Effect:  VerdictClosed,
	},
	{
		ID:      RuleControlOversize,
		Clauses: []string{"rfc6455#section-5.5", "rfc6455#section-7.1.7"},
		Quote:   "All control frames MUST have a payload length of 125 bytes or less and MUST NOT be fragmented.",
		Effect:  VerdictClosed,
	},
	{
		ID:      RuleControlFragmented,
		Clauses: []string{"rfc6455#section-5.5", "rfc6455#section-5.4", "rfc6455#section-7.1.7"},
		Quote:   "All control frames ... MUST NOT be fragmented. Control frames ... MAY be injected in the middle of a fragmented message.",
		Effect:  VerdictClosed,
	},
	{
		ID:      RuleOrphanContinuation,
		Clauses: []string{"rfc6455#section-5.4", "rfc6455#section-7.1.7"},
		Quote:   "A fragmented message consists of a single frame with the FIN bit clear and an opcode other than 0, followed by zero or more frames with the FIN bit clear and the opcode set to 0, and terminated by a single frame with the FIN bit set and an opcode of 0. A continuation frame outside that sequence has no message to continue.",
		Effect:  VerdictClosed,
	},
	{
		ID:      RuleInterleavedData,
		Clauses: []string{"rfc6455#section-5.4", "rfc6455#section-7.1.7"},
		Quote:   "The fragments of one message MUST NOT be interleaved between the fragments of another message. Control frames MAY be injected in the middle of a fragmented message; data frames may not.",
		Effect:  VerdictClosed,
	},
	{
		ID:      RuleCloseBodyLength1,
		Clauses: []string{"rfc6455#section-5.5.1", "rfc6455#section-7.1.7"},
		Quote:   "If there is a body, the first two bytes of the body MUST be a 2-byte unsigned integer ... representing a status code. A Close body of exactly one octet cannot carry one.",
		Effect:  VerdictClosed,
	},
	{
		ID:      RuleCloseCodeInvalid,
		Clauses: []string{"rfc6455#section-7.4", "rfc6455#section-7.4.1", "rfc6455#section-7.4.2", "rfc6455#section-7.1.7"},
		Quote:   "Status codes in the range 0-999 are not used. 1000-2999 are reserved for definition by this protocol, and this protocol defines 1000-1011. 1005, 1006 and 1015 are designated for use in applications and MUST NOT be set as a status code in a Close control frame. 3000-3999 and 4000-4999 are available to libraries and to private use.",
		Effect:  VerdictClosed,
	},
	{
		ID:      RuleCloseReasonNotUTF8,
		Clauses: []string{"rfc6455#section-5.5.1", "rfc6455#section-8.1"},
		Quote:   "Following the 2-byte integer, the body MAY contain UTF-8-encoded data ... When an endpoint is to interpret a byte stream as UTF-8 but finds that the byte stream is not, in fact, a valid UTF-8 stream, that endpoint MUST Fail the WebSocket Connection.",
		Effect:  VerdictClosed,
	},
	{
		ID:      RuleTextNotUTF8,
		Clauses: []string{"rfc6455#section-5.6", "rfc6455#section-8.1", "rfc6455#section-7.1.7"},
		Quote:   "Text: The Payload data is text data encoded as UTF-8. When an endpoint is to interpret a byte stream as UTF-8 but finds that the byte stream is not, in fact, a valid UTF-8 stream, that endpoint MUST Fail the WebSocket Connection.",
		Effect:  VerdictClosed,
	},
	{
		ID:      RuleNoViolation,
		Clauses: []string{"rfc6455#section-7.1.7"},
		Quote:   "Certain algorithms and specifications require an endpoint to Fail the WebSocket Connection. No such provision fired on this scenario's octets, so nothing in RFC 6455 takes the endpoint out of the OPEN state.",
		Effect:  VerdictOpen,
	},

	{
		ID:      AbstainNonOpenInitialState,
		Clauses: []string{"rfc6455#section-7.1.3", "rfc6455#section-7.1.4"},
		Quote:   "RFC 6455 defines The WebSocket Closing Handshake is Started and The WebSocket Connection is Closed; it does not define a readyState, and the scenario's declared non-open initial state is a state of the W3C WebSocket API rather than of this protocol.",
	},
	{
		ID:      AbstainClosingHandshake,
		Clauses: []string{"rfc6455#section-5.5.1", "rfc6455#section-7.1.2", "rfc6455#section-7.1.3", "rfc6455#section-7.1.4"},
		Quote:   "Receipt of a valid Close frame starts the closing handshake and obliges the endpoint to send a Close frame in response. Whether the endpoint is then CLOSING or CLOSED is a distinction of the W3C WebSocket API's readyState, not of RFC 6455, and turns on transport state these octets do not carry.",
	},
	{
		ID:      AbstainLocalAPIAction,
		Clauses: []string{"rfc6455#section-7.1.7"},
		Quote:   "Failing the WebSocket Connection is required where another algorithm or specification requires it. RFC 6455 states no provision governing how an endpoint answers a local application request to send a frame, including a request carrying an undefined status code, so this derivation has no rule to apply.",
	},
	{
		ID:      AbstainHarnessLimit,
		Clauses: []string{"rfc6455#section-5.2"},
		Quote:   "RFC 6455 permits payload lengths up to 2^63-1 and states no bound on the number of frames or octets an endpoint accepts. The scenario's own declared limits are a property of the harness, so a run that meets one is outside what these rules decide.",
	},
	{
		ID:      AbstainTruncatedTrailer,
		Clauses: []string{"rfc6455#section-5.2"},
		Quote:   "A frame whose header is not yet complete is not a malformed frame; the endpoint waits for more octets. Where the stream ends inside a header this derivation does not decide the ready state, because whether more octets follow is not stated by the scenario.",
	},
}

var ruleByID = func() map[string]Rule {
	m := make(map[string]Rule, len(rules))
	for _, r := range rules {
		if _, dup := m[r.ID]; dup {
			panic("rfcneutral: duplicate rule id " + r.ID)
		}
		m[r.ID] = r
	}
	return m
}()

// Rules returns the whole transcribed table, sorted by id, so a caller can
// record what this derivation was applying on the run that produced it.
func Rules() []Rule {
	out := append([]Rule(nil), rules...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// LookupRule returns the transcribed rule behind a decision.
func LookupRule(id string) (Rule, bool) {
	r, ok := ruleByID[id]
	return r, ok
}

// validCloseCode reports whether code may appear as the status code of a Close
// control frame on the wire, under RuleCloseCodeInvalid's reading of section
// 7.4. 1004 is reserved and undefined; 1005, 1006 and 1015 are designated for
// applications and MUST NOT be sent; 1012-2999 are reserved for definition by
// this protocol and this protocol does not define them.
func validCloseCode(code uint16) bool {
	switch {
	case code >= 1000 && code <= 1003:
		return true
	case code >= 1007 && code <= 1011:
		return true
	case code >= 3000 && code <= 4999:
		return true
	default:
		return false
	}
}
