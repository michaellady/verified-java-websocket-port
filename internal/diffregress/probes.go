// Package diffregress holds the corpus-invisible differential regression set:
// oracle requests that are deliberately NOT in the 74-scenario public corpus,
// recorded with BOTH arms (the real pinned Java-WebSocket 1.6.0 oracle and the
// ws_core Rust harness) so the agreement between them is committed evidence
// rather than an ephemeral audit result.
//
// The three probe classes generalize the three Rust defect classes the
// cross-plane defect audit enumerated on the Codex plane:
//
//   - Class A "consumption": rejected-input consumption accounting, i.e. the
//     per-site consumed_bytes arithmetic when a frame is rejected part-way
//     through a multi-frame chunk. The public corpus only ever rejects at
//     offset 0, so the offset arithmetic is corpus-invisible.
//   - Class B "closed-bytes": byte counting for input refused because the
//     connection is already CLOSED.
//   - Class D "empty-chunk": handling of a zero-length input chunk, in every
//     ready state.
//
// Probe REQUESTS are generated from this Go table, never hand-edited, so the
// committed JSONL is reproducible and every request_digest is recomputed rather
// than trusted. Probe RESULTS are recorded from real process runs only: the
// Java arm is always produced by executing the pinned oracle. No expected value
// in this package was predicted.
package diffregress

import (
	"encoding/base64"
	"fmt"

	"github.com/michaellady/verified-java-websocket-port/internal/corpora"
)

// Protocol identity shared with the java-oracle adapter and ws-oracle-harness.
const (
	Protocol = "java-websocket-oracle"
	Version  = "1.0.0"
)

// Class names one of the three defect classes a probe generalizes.
type Class string

const (
	// ClassConsumption is rejected-input consumption accounting (defect A).
	ClassConsumption Class = "consumption"
	// ClassClosedBytes is closed-state byte counting (defects B and C).
	ClassClosedBytes Class = "closed-bytes"
	// ClassEmptyChunk is empty-chunk-after-close handling (defects D and E).
	ClassEmptyChunk Class = "empty-chunk"
)

// Origin records how a probe entered this set. It is deliberately part of the
// committed record: a reader must be able to tell a probe recovered verbatim
// from the audit's scratch file from one this package authored.
type Origin string

const (
	// OriginRecovered means the probe bytes were recovered verbatim from the
	// defect audit's scratch file /tmp/us020x/probes.jsonl.
	OriginRecovered Origin = "recovered"
	// OriginReconstructed means the probe was rebuilt from the audit report's
	// prose because the scratch file was gone.
	OriginReconstructed Origin = "reconstructed"
	// OriginNew means this package authored the probe to widen coverage of the
	// same three classes beyond what the audit ran.
	OriginNew Origin = "new"
)

// Probe is one corpus-invisible differential request.
type Probe struct {
	ID           string
	Class        Class
	Origin       Origin
	Role         string
	InitialState string
	// Chunks are the raw input byte chunks, in order. A nil or empty chunk is
	// a deliberate zero-length input step.
	Chunks [][]byte
	// Rationale states what the probe stresses that the public corpus does not.
	Rationale string
}

// limits mirrors the limits block the committed 74 public requests carry, so a
// probe differs from a corpus request only in its identity and its steps.
func limits() map[string]any {
	return map[string]any{
		"max_actions":        64,
		"max_buffered_bytes": 65536,
		"max_frames":         64,
		"max_input_bytes":    65536,
		"max_output_bytes":   4194304,
	}
}

// maskedFrame builds a client-to-server (masked) WebSocket frame with the given
// first byte and payload, using a fixed masking key. Payloads up to 65535 bytes
// are encoded, taking the 2-byte extended length form above 125 so the extended
// length arithmetic is exercised.
func maskedFrame(first byte, payload []byte, key [4]byte) []byte {
	frame := []byte{first}
	switch n := len(payload); {
	case n <= 125:
		frame = append(frame, byte(0x80|n))
	default:
		frame = append(frame, 0x80|126, byte(n>>8), byte(n))
	}
	frame = append(frame, key[:]...)
	for i, b := range payload {
		frame = append(frame, b^key[i%4])
	}
	return frame
}

// Frame first bytes. 0x80 is FIN; 0x40/0x20/0x10 are RSV1/RSV2/RSV3.
const (
	finText    = 0x81
	rsv1Text   = 0x81 | 0x40
	rsv2Text   = 0x81 | 0x20
	rsv3Text   = 0x81 | 0x10
	nonFinPing = 0x09 // a fragmented control frame: control opcode with FIN clear
)

var (
	keyA = [4]byte{0xaa, 0xbb, 0xcc, 0xdd}
	keyB = [4]byte{0x74, 0xb3, 0xd8, 0xd2}
)

// validHi is the 8-byte masked text frame carrying "hi".
func validHi() []byte { return maskedFrame(finText, []byte("hi"), keyA) }

// validOk is the 8-byte masked text frame carrying "ok".
func validOk() []byte { return maskedFrame(finText, []byte("ok"), keyA) }

// rsv2Frame is the 9-byte RSV2 frame from public scenario us005.pub.0005.
func rsv2Frame() []byte { return maskedFrame(rsv2Text, []byte{0x7c, 0x5a, 0x5d}, keyB) }

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func repeatBytes(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

// Catalog returns the ordered probe set. The order is the committed JSONL order.
func Catalog() []Probe {
	return []Probe{
		// ---- recovered from the defect audit (/tmp/us020x/probes.jsonl) ----
		{
			ID: "xd.a1.rsv-midchunk", Class: ClassConsumption, Origin: OriginRecovered,
			Role: "server", InitialState: "open",
			Chunks:    [][]byte{concat(validHi(), rsv2Frame(), validOk())},
			Rationale: "valid frame + RSV frame + valid frame in one 25-byte chunk: is consumed the offset past the rejected frame, or the whole chunk? The public corpus only rejects at offset 0.",
		},
		{
			ID: "xd.a2.rsv-split", Class: ClassConsumption, Origin: OriginRecovered,
			Role: "server", InitialState: "open",
			Chunks:    [][]byte{rsv2Frame()[:5], rsv2Frame()[5:]},
			Rationale: "RSV frame split across two chunks (5+4, splitting inside the masking key), exercising the chunk-start subtraction in the consumed arithmetic.",
		},
		{
			ID: "xd.b1.closed-64bytes", Class: ClassClosedBytes, Origin: OriginRecovered,
			Role: "server", InitialState: "closed",
			Chunks:    [][]byte{repeatBytes(64)},
			Rationale: "64-byte non-empty chunk into CLOSED: are refused bytes counted?",
		},
		{
			ID: "xd.b2.closed-empty-then-bytes", Class: ClassClosedBytes, Origin: OriginRecovered,
			Role: "server", InitialState: "closed",
			Chunks:    [][]byte{{}, {0x5d, 0x87, 0x0a}},
			Rationale: "empty chunk then non-empty chunk into CLOSED: the empty no-op must not arm the counters for the refused chunk.",
		},
		{
			ID: "xd.b3.closed-valid-frame", Class: ClassClosedBytes, Origin: OriginRecovered,
			Role: "server", InitialState: "closed",
			Chunks:    [][]byte{validHi()},
			Rationale: "a well-formed complete frame into CLOSED: the state check must precede framing, so well-formedness cannot change the counts.",
		},
		{
			ID: "xd.d1.closing-empty", Class: ClassEmptyChunk, Origin: OriginRecovered,
			Role: "server", InitialState: "closing",
			Chunks:    [][]byte{{}},
			Rationale: "empty chunk in CLOSING.",
		},
		{
			ID: "xd.d2.open-empty", Class: ClassEmptyChunk, Origin: OriginRecovered,
			Role: "server", InitialState: "open",
			Chunks:    [][]byte{{}},
			Rationale: "empty chunk in OPEN.",
		},
		{
			ID: "xd.d3.closed-empty-twice", Class: ClassEmptyChunk, Origin: OriginRecovered,
			Role: "server", InitialState: "closed",
			Chunks:    [][]byte{{}, {}},
			Rationale: "two empty chunks in CLOSED: the no-op must be repeatable, not merely tolerated once.",
		},

		// ---- new: class A, consumption accounting ----
		{
			ID: "xd.a3.rsv-after-two-valid", Class: ClassConsumption, Origin: OriginNew,
			Role: "server", InitialState: "open",
			Chunks:    [][]byte{concat(validHi(), validOk(), rsv2Frame())},
			Rationale: "two valid frames before the rejected frame: consumed must advance past BOTH prefixes, not just one.",
		},
		{
			ID: "xd.a4.rsv-first-then-valid", Class: ClassConsumption, Origin: OriginNew,
			Role: "server", InitialState: "open",
			Chunks:    [][]byte{concat(rsv2Frame(), validHi())},
			Rationale: "rejected frame at offset 0 followed by a valid frame: consumed must stop at the rejection and must not run on into the trailing valid frame.",
		},
		{
			ID: "xd.a5.rsv1-midchunk", Class: ClassConsumption, Origin: OriginNew,
			Role: "server", InitialState: "open",
			Chunks:    [][]byte{concat(validHi(), maskedFrame(rsv1Text, []byte{0x01, 0x02, 0x03}, keyB), validOk())},
			Rationale: "same offset arithmetic driven by RSV1 rather than RSV2, so the site is not special-cased to one reserved bit.",
		},
		{
			ID: "xd.a6.rsv3-midchunk", Class: ClassConsumption, Origin: OriginNew,
			Role: "server", InitialState: "open",
			Chunks:    [][]byte{concat(validHi(), maskedFrame(rsv3Text, []byte{0x01, 0x02, 0x03}, keyB), validOk())},
			Rationale: "same offset arithmetic driven by RSV3.",
		},
		{
			ID: "xd.a7.rsv-extended-length", Class: ClassConsumption, Origin: OriginNew,
			Role: "server", InitialState: "open",
			Chunks:    [][]byte{concat(validHi(), maskedFrame(rsv2Text, repeatBytes(126), keyB), validOk())},
			Rationale: "rejected frame using the 2-byte extended length form: consumed must span header+extended-length+mask+payload, an arithmetic path the corpus never rejects on.",
		},
		{
			ID: "xd.a8.rsv-split-three", Class: ClassConsumption, Origin: OriginNew,
			Role: "server", InitialState: "open",
			Chunks:    [][]byte{rsv2Frame()[:2], rsv2Frame()[2:6], rsv2Frame()[6:]},
			Rationale: "rejected frame split across three chunks, so the chunk-start subtraction is exercised at a non-first, non-last boundary.",
		},
		{
			ID: "xd.a9.control-fin-midchunk", Class: ClassConsumption, Origin: OriginNew,
			Role: "server", InitialState: "open",
			Chunks:    [][]byte{concat(validHi(), maskedFrame(nonFinPing, []byte{0x01, 0x02, 0x03}, keyB), validOk())},
			Rationale: "the OTHER post-payload rejection the batch-A borrow receipt moved off header time: a fragmented control frame mid-chunk, same offset arithmetic as the RSV site.",
		},

		// ---- new: class B, closed-state byte counting ----
		{
			ID: "xd.b4.closed-multi-chunk", Class: ClassClosedBytes, Origin: OriginNew,
			Role: "server", InitialState: "closed",
			Chunks:    [][]byte{{0x01, 0x02}, {0x03, 0x04, 0x05}, {0x06}},
			Rationale: "several non-empty chunks into CLOSED: the refusal must fire on the first and must not accumulate across steps.",
		},
		{
			ID: "xd.b5.closed-partial-header", Class: ClassClosedBytes, Origin: OriginNew,
			Role: "server", InitialState: "closed",
			Chunks:    [][]byte{{0x81}},
			Rationale: "a single byte (an incomplete frame header) into CLOSED: an input too short to frame at all must still be refused with zero counts.",
		},
		{
			ID: "xd.b6.closed-rsv-frame", Class: ClassClosedBytes, Origin: OriginNew,
			Role: "server", InitialState: "closed",
			Chunks:    [][]byte{rsv2Frame()},
			Rationale: "an independently-invalid frame into CLOSED: the state refusal must win over the framing rejection, so the error identity is STATE_VIOLATION and not the RSV error.",
		},
		{
			ID: "xd.b7.closing-nonempty", Class: ClassClosedBytes, Origin: OriginNew,
			Role: "server", InitialState: "closing",
			Chunks:    [][]byte{validHi()},
			Rationale: "non-empty valid frame in CLOSING rather than CLOSED: pins whether the closed-state byte refusal extends to CLOSING, which the corpus does not settle.",
		},

		// ---- new: class D, empty-chunk handling ----
		{
			ID: "xd.d4.closing-empty-twice", Class: ClassEmptyChunk, Origin: OriginNew,
			Role: "server", InitialState: "closing",
			Chunks:    [][]byte{{}, {}},
			Rationale: "repeated empty chunks in CLOSING, the CLOSING analogue of xd.d3.",
		},
		{
			ID: "xd.d5.open-empty-then-frame", Class: ClassEmptyChunk, Origin: OriginNew,
			Role: "server", InitialState: "open",
			Chunks:    [][]byte{{}, validHi()},
			Rationale: "empty chunk then a valid frame in OPEN: the no-op must leave the subsequent frame's accounting untouched.",
		},
		{
			ID: "xd.d6.open-empty-between-frame-halves", Class: ClassEmptyChunk, Origin: OriginNew,
			Role: "server", InitialState: "open",
			Chunks:    [][]byte{validHi()[:4], {}, validHi()[4:]},
			Rationale: "cross-class: an empty chunk interposed between the two halves of a split frame. If the empty no-op perturbed the reassembly offset, only this shape would show it.",
		},
		{
			ID: "xd.d7.open-empty-then-rsv-midchunk", Class: ClassEmptyChunk, Origin: OriginNew,
			Role: "server", InitialState: "open",
			Chunks:    [][]byte{{}, concat(validHi(), rsv2Frame(), validOk())},
			Rationale: "cross-class: an empty no-op immediately before the xd.a1 shape, so a no-op that silently shifted the per-site consumed base would diverge here.",
		},
	}
}

// RequestObject builds the canonical oracle request for a probe, computing the
// request_digest over the canonical form exactly as java-oracle's OracleMain and
// ws-oracle-harness both recompute and verify it. A probe whose digest were
// wrong would be REFUSED by both implementations, so a probe that runs at all is
// a probe both sides agreed was well formed.
func RequestObject(p Probe) (map[string]any, error) {
	steps := make([]any, 0, len(p.Chunks))
	for _, chunk := range p.Chunks {
		steps = append(steps, map[string]any{
			"kind":        "bytes",
			"data_base64": base64.StdEncoding.EncodeToString(chunk),
		})
	}
	request := map[string]any{
		"initial_state": p.InitialState,
		"limits":        limits(),
		"protocol":      Protocol,
		"version":       Version,
		"request_id":    p.ID,
		"role":          p.Role,
		"steps":         steps,
	}
	canonical, err := corpora.CanonicalJSON(request)
	if err != nil {
		return nil, fmt.Errorf("canonicalize probe %s: %w", p.ID, err)
	}
	request["request_digest"] = corpora.DigestSHA256(canonical)
	return request, nil
}

// RequestLine renders one probe as a canonical JSONL request line.
func RequestLine(p Probe) ([]byte, error) {
	request, err := RequestObject(p)
	if err != nil {
		return nil, err
	}
	return corpora.CanonicalJSON(request)
}

// RequestsJSONL renders the whole catalog as newline-terminated JSONL.
func RequestsJSONL() ([]byte, error) {
	var out []byte
	for _, p := range Catalog() {
		line, err := RequestLine(p)
		if err != nil {
			return nil, err
		}
		out = append(out, line...)
		out = append(out, '\n')
	}
	return out, nil
}
