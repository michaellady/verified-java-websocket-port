// Package diffregress holds a differential regression set: oracle requests that
// are NOT in the 74-scenario public corpus, recorded with BOTH arms (the real
// pinned Java-WebSocket 1.6.0 oracle and the ws_core Rust harness) so the
// agreement between them is committed evidence rather than an ephemeral audit
// result.
//
// The three probe classes generalize the three Rust defect classes the
// cross-plane defect audit enumerated on the Codex plane:
//
//   - Class A "consumption": rejected-input consumption accounting, i.e. the
//     per-site consumed_bytes arithmetic when a frame is rejected part-way
//     through a multi-frame chunk.
//   - Class B "closed-bytes": byte counting for input refused because the
//     connection is already CLOSED.
//   - Class D "empty-chunk": handling of a zero-length input chunk, in every
//     ready state.
//
// ON "CORPUS-INVISIBLE". Not every probe here is corpus-invisible, and the set
// does not claim to be. A review round found that an earlier version asserted
// invisibility in prose for probes the 74 already pinned — notably xd.b7, which
// us005.pub.0051 covers exactly. Every probe now carries an audited
// Invisibility verdict naming the public scenario that pins it where one
// exists. Of 23 probes, 4 are genuinely invisible, 12 are partial, and 7 are
// redundant with the corpus. The redundant ones are KEPT: they cost nothing to
// run and a redundant differential check against the real Java oracle is still
// a real check. They simply may not be cited as coverage the corpus lacks.
//
// These verdicts survived an independent adversarial re-audit that downgraded
// nine of them. Where that audit and this catalog still differ, the more
// conservative verdict is recorded and the dissent is noted in the probe's
// InvisibilityNote (xd.a5, xd.a6, xd.a9).
//
// What is genuinely not reachable by the 74: the corpus has multi-frame chunks
// but only of valid frames; splits frames but only valid ones; and feeds
// zero-length chunks only as standalone steps in OPEN and CLOSED. It never
// FRAMING-rejects at a nonzero offset. (Precision owed to the audit: us005.pub.0032
// does error on the second frame of a two-frame chunk, but as a frame-cap after
// the whole chunk was consumed, so consumed=16 equals the chunk length and it
// cannot discriminate offset arithmetic.)
//
// That reduces to three genuinely unreachable behaviours: a rejection preceded
// by a consumed frame in the same chunk; the same at the fragmented-control
// rejection site; and the same where the rejected frame uses the 2-byte
// extended-length form.
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

// Invisibility records, per probe, whether the 74-scenario public corpus
// already pins the behaviour the probe exercises.
//
// This is deliberately DATA rather than prose. An earlier round asserted in
// prose that xd.b7 exercised surface the corpus could not see; public case
// us005.pub.0051 already pinned it. Encoding the claim per probe, with the
// pinning scenario named, makes the claim checkable instead of rhetorical.
type Invisibility string

const (
	// GenuinelyInvisible means no public scenario pins this behaviour.
	GenuinelyInvisible Invisibility = "genuinely_invisible"
	// PartiallyInvisible means the corpus pins a weaker or related version and
	// the probe adds something specific beyond it.
	PartiallyInvisible Invisibility = "partial"
	// Redundant means a public scenario already pins this behaviour, so a
	// defect the probe would catch would also be caught by the corpus.
	Redundant Invisibility = "redundant"
)

// Probe is one differential request aimed at the three defect classes.
type Probe struct {
	ID           string
	Class        Class
	Origin       Origin
	Role         string
	InitialState string
	// Chunks are the raw input byte chunks, in order. A nil or empty chunk is
	// a deliberate zero-length input step.
	Chunks [][]byte
	// Rationale states what the probe stresses.
	Rationale string
	// Invisibility is the audited verdict on whether the public corpus already
	// pins this behaviour.
	Invisibility Invisibility
	// PinnedBy names the public scenario ids that already pin this behaviour.
	// It MUST be non-empty when Invisibility is Redundant or PartiallyInvisible,
	// and MUST be empty when GenuinelyInvisible. A test enforces that.
	PinnedBy []string
	// InvisibilityNote justifies the verdict in one line.
	InvisibilityNote string
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
			Chunks:           [][]byte{concat(validHi(), rsv2Frame(), validOk())},
			Rationale:        "valid frame + RSV frame + valid frame in one 25-byte chunk: is consumed the offset past the rejected frame, or the whole chunk? The public corpus only rejects at offset 0.",
			Invisibility:     GenuinelyInvisible,
			PinnedBy:         nil,
			InvisibilityNote: "The corpus has multi-frame chunks (us005.pub.0043/0053) but every frame in them is VALID, and it has RSV rejections (0005/0029/0058) but always at offset 0. No public case rejects a frame AFTER a successfully consumed frame in the same chunk, which is the arithmetic this pins.",
		},
		{
			ID: "xd.a2.rsv-split", Class: ClassConsumption, Origin: OriginRecovered,
			Role: "server", InitialState: "open",
			Chunks:           [][]byte{rsv2Frame()[:5], rsv2Frame()[5:]},
			Rationale:        "RSV frame split across two chunks (5+4, splitting inside the masking key), exercising the chunk-start subtraction in the consumed arithmetic.",
			Invisibility:     PartiallyInvisible,
			PinnedBy:         []string{"us005.pub.0005", "us005.pub.0072"},
			InvisibilityNote: "DOWNGRADED after independent audit. The observed counts 9/9/frames=0 are IDENTICAL to us005.pub.0005, and us005.pub.0072 already pins carry-buffer consumed-summing on the OK path. Only the combination (a frame reassembled from a carry buffer and then rejected) is new.",
		},
		{
			ID: "xd.b1.closed-64bytes", Class: ClassClosedBytes, Origin: OriginRecovered,
			Role: "server", InitialState: "closed",
			Chunks:           [][]byte{repeatBytes(64)},
			Rationale:        "64-byte non-empty chunk into CLOSED: are refused bytes counted?",
			Invisibility:     Redundant,
			PinnedBy:         []string{"us005.pub.0015"},
			InvisibilityNote: "state-bytes-in-closed 0015 already pins non-empty bytes into CLOSED at consumed=0/input=0/frames=0 with STATE_VIOLATION. A larger chunk exercises the same rule; a defect here would be caught by 0015.",
		},
		{
			ID: "xd.b2.closed-empty-then-bytes", Class: ClassClosedBytes, Origin: OriginRecovered,
			Role: "server", InitialState: "closed",
			Chunks:           [][]byte{{}, {0x5d, 0x87, 0x0a}},
			Rationale:        "empty chunk then non-empty chunk into CLOSED: the empty no-op must not arm the counters for the refused chunk.",
			Invisibility:     PartiallyInvisible,
			PinnedBy:         []string{"us005.pub.0015", "us005.pub.0017"},
			InvisibilityNote: "Both halves are pinned separately (0017 empty-in-closed, 0015 bytes-in-closed); the SEQUENCE is not, so only the interaction is new.",
		},
		{
			ID: "xd.b3.closed-valid-frame", Class: ClassClosedBytes, Origin: OriginRecovered,
			Role: "server", InitialState: "closed",
			Chunks:           [][]byte{validHi()},
			Rationale:        "a well-formed complete frame into CLOSED. (us005.pub.0015 already pins this: its own bytes are framing-invalid, so it already separates the state check from framing.)",
			Invisibility:     Redundant,
			PinnedBy:         []string{"us005.pub.0015"},
			InvisibilityNote: "DOWNGRADED after independent audit. The premise was that 0015 feeds a benign input; it does not. 0015's bytes 5d 87 0a have FIN=0, RSV1=1, RSV3=1 and reserved opcode 0xd, so 0015 ALREADY discriminates state-check-before-framing. The CLOSED guard is one content-agnostic test (state == CLOSED && bytes.length != 0), so a well-formed frame takes the identical branch.",
		},
		{
			ID: "xd.d1.closing-empty", Class: ClassEmptyChunk, Origin: OriginRecovered,
			Role: "server", InitialState: "closing",
			Chunks:           [][]byte{{}},
			Rationale:        "empty chunk in CLOSING.",
			Invisibility:     PartiallyInvisible,
			PinnedBy:         []string{"us005.pub.0017", "us005.pub.0045"},
			InvisibilityNote: "DOWNGRADED after independent audit. The empty-chunk short-circuit is a single STATE-AGNOSTIC branch in OracleEngine.input(), and the corpus pins it in CLOSED (0017) and OPEN (0045). CLOSING adds only that a hypothetical per-state-coded no-op would diverge there.",
		},
		{
			ID: "xd.d2.open-empty", Class: ClassEmptyChunk, Origin: OriginRecovered,
			Role: "server", InitialState: "open",
			Chunks:           [][]byte{{}},
			Rationale:        "empty chunk in OPEN. This is a literal duplicate of public scenario us005.pub.0045.",
			Invisibility:     Redundant,
			PinnedBy:         []string{"us005.pub.0045"},
			InvisibilityNote: "LITERAL DUPLICATE: identical role, initial_state, limits and steps to us005.pub.0045, verified field by field. This is a duplicate of a public scenario, not a probe.",
		},
		{
			ID: "xd.d3.closed-empty-twice", Class: ClassEmptyChunk, Origin: OriginRecovered,
			Role: "server", InitialState: "closed",
			Chunks:           [][]byte{{}, {}},
			Rationale:        "two empty chunks in CLOSED: the no-op must be repeatable, not merely tolerated once.",
			Invisibility:     PartiallyInvisible,
			PinnedBy:         []string{"us005.pub.0017"},
			InvisibilityNote: "0017 pins a single empty chunk in CLOSED. This adds only that the no-op is repeatable rather than tolerated once.",
		},

		// ---- new: class A, consumption accounting ----
		{
			ID: "xd.a3.rsv-after-two-valid", Class: ClassConsumption, Origin: OriginNew,
			Role: "server", InitialState: "open",
			Chunks:           [][]byte{concat(validHi(), validOk(), rsv2Frame())},
			Rationale:        "two valid frames before the rejected frame: consumed must advance past BOTH prefixes, not just one.",
			Invisibility:     GenuinelyInvisible,
			PinnedBy:         nil,
			InvisibilityNote: "No public case rejects after any consumed prefix, let alone two. NOTE a real weakness surfaced by the independent audit: because consumed=25 equals the chunk length here, this probe alone cannot catch a 'consume the whole chunk' over-count. xd.a1 (consumed=17 of 25) is the discriminating one.",
		},
		{
			ID: "xd.a4.rsv-first-then-valid", Class: ClassConsumption, Origin: OriginNew,
			Role: "server", InitialState: "open",
			Chunks:           [][]byte{concat(rsv2Frame(), validHi())},
			Rationale:        "rejected frame at offset 0 followed by a valid frame: consumed must stop at the rejection and must not run on into the trailing valid frame.",
			Invisibility:     PartiallyInvisible,
			PinnedBy:         []string{"us005.pub.0031", "us005.pub.0036", "us005.pub.0057", "us005.pub.0059", "us005.pub.0065"},
			InvisibilityNote: "The rule that a rejection stops consumption and leaves trailing bytes counted-but-unconsumed is pinned FIVE ways (0036/0065 consumed=2 of 8, 0031 2 of 86, 0057 2 of 173, 0059 2 of 134). Those all pin it at header-time sites; this adds the post-payload RSV site (consumed=9 of 17).",
		},
		{
			ID: "xd.a5.rsv1-midchunk", Class: ClassConsumption, Origin: OriginNew,
			Role: "server", InitialState: "open",
			Chunks:           [][]byte{concat(validHi(), maskedFrame(rsv1Text, []byte{0x01, 0x02, 0x03}, keyB), validOk())},
			Rationale:        "the same offset arithmetic driven by RSV1 rather than RSV2. (The corpus already shows the site is not special-cased to one reserved bit: us005.pub.0029 pins RSV1 at offset 0.)",
			Invisibility:     PartiallyInvisible,
			PinnedBy:         []string{"us005.pub.0029"},
			InvisibilityNote: "Stated rationale FALSIFIED: 0029 already pins RSV1 rejection at 9/9/frames=0, so the site is demonstrably not special-cased to one reserved bit. The only increment is the nonzero offset, which xd.a1 already covers. The independent audit labelled this genuinely_invisible on the stricter reading that no case pins mid-chunk RSV1; recorded as partial here because 0029 pins the behaviour and only the offset is new.",
		},
		{
			ID: "xd.a6.rsv3-midchunk", Class: ClassConsumption, Origin: OriginNew,
			Role: "server", InitialState: "open",
			Chunks:           [][]byte{concat(validHi(), maskedFrame(rsv3Text, []byte{0x01, 0x02, 0x03}, keyB), validOk())},
			Rationale:        "the same offset arithmetic driven by RSV3. (us005.pub.0058 already pins RSV3 at offset 0.)",
			Invisibility:     PartiallyInvisible,
			PinnedBy:         []string{"us005.pub.0058"},
			InvisibilityNote: "Stated rationale FALSIFIED: 0058 already pins RSV3 rejection at 9/9/frames=0. Only the nonzero offset is new, which xd.a1 already covers. Audit dissent noted as for xd.a5.",
		},
		{
			ID: "xd.a7.rsv-extended-length", Class: ClassConsumption, Origin: OriginNew,
			Role: "server", InitialState: "open",
			Chunks:           [][]byte{concat(validHi(), maskedFrame(rsv2Text, repeatBytes(126), keyB), validOk())},
			Rationale:        "rejected frame using the 2-byte extended length form: consumed must span header+extended-length+mask+payload, an arithmetic path the corpus never rejects on.",
			Invisibility:     GenuinelyInvisible,
			PinnedBy:         nil,
			InvisibilityNote: "The corpus pins extended-length ACCEPTANCE (0011 consumed=134, 0013 consumed=923) and rejections at offset 0, but never a rejected frame that itself uses the 2-byte extended length form, and never one at a nonzero offset. consumed=142=8+134 exercises both at once.",
		},
		{
			ID: "xd.a8.rsv-split-three", Class: ClassConsumption, Origin: OriginNew,
			Role: "server", InitialState: "open",
			Chunks:           [][]byte{rsv2Frame()[:2], rsv2Frame()[2:6], rsv2Frame()[6:]},
			Rationale:        "rejected frame split across three chunks, so the chunk-start subtraction is exercised at a non-first, non-last boundary.",
			Invisibility:     PartiallyInvisible,
			PinnedBy:         []string{"us005.pub.0005", "us005.pub.0072"},
			InvisibilityNote: "DOWNGRADED after independent audit. Counts 9/9/frames=0 are identical to 0005; over xd.a2 this adds only a chunk boundary that is neither first nor last. Marginal.",
		},
		{
			ID: "xd.a9.control-fin-midchunk", Class: ClassConsumption, Origin: OriginNew,
			Role: "server", InitialState: "open",
			Chunks:           [][]byte{concat(validHi(), maskedFrame(nonFinPing, []byte{0x01, 0x02, 0x03}, keyB), validOk())},
			Rationale:        "the OTHER post-payload rejection the batch-A borrow receipt moved off header time: a fragmented control frame mid-chunk, same offset arithmetic as the RSV site.",
			Invisibility:     PartiallyInvisible,
			PinnedBy:         []string{"us005.pub.0020"},
			InvisibilityNote: "control-nonfin 0020 already pins the fragmented-control rejection at offset 0 (consumed=10, frames=0), so the earlier claim that this probe independently confirms the batch-A borrow correction was WRONG: 0020 confirms it. The increment is the nonzero offset at a second post-payload site. The independent audit rated this genuinely_invisible as a real increment over xd.a1 (different rejection site); recorded as partial here because 0020 pins the site.",
		},

		// ---- new: class B, closed-state byte counting ----
		{
			ID: "xd.b4.closed-multi-chunk", Class: ClassClosedBytes, Origin: OriginNew,
			Role: "server", InitialState: "closed",
			Chunks:           [][]byte{{0x01, 0x02}, {0x03, 0x04, 0x05}, {0x06}},
			Rationale:        "several non-empty chunks into CLOSED. NOTE: only chunk 0 ever executes - OracleEngine.run() has no try/catch, so the step-0 STATE_VIOLATION aborts the run. The trailing chunks are inert.",
			Invisibility:     Redundant,
			PinnedBy:         []string{"us005.pub.0015"},
			InvisibilityNote: "DOWNGRADED after independent audit, and the stated rationale is UNREACHABLE BY CONSTRUCTION: OracleEngine.run() has no try/catch, so the STATE_VIOLATION thrown on step 0 propagates out of the step loop and chunks 1 and 2 are never fed. The probe cannot test non-accumulation across steps because the later steps do not execute.",
		},
		{
			ID: "xd.b5.closed-partial-header", Class: ClassClosedBytes, Origin: OriginNew,
			Role: "server", InitialState: "closed",
			Chunks:           [][]byte{{0x81}},
			Rationale:        "a single byte (an incomplete frame header) into CLOSED: an input too short to frame at all must still be refused with zero counts.",
			Invisibility:     Redundant,
			PinnedBy:         []string{"us005.pub.0015"},
			InvisibilityNote: "0015's own 3-byte chunk is already an incomplete frame in CLOSED. A 1-byte chunk exercises the identical rule; a defect here would be caught by 0015.",
		},
		{
			ID: "xd.b6.closed-rsv-frame", Class: ClassClosedBytes, Origin: OriginNew,
			Role: "server", InitialState: "closed",
			Chunks:           [][]byte{rsv2Frame()},
			Rationale:        "an independently-invalid frame into CLOSED. (us005.pub.0015 already pins this; its first byte carries RSV1+RSV3 and reserved opcode 0xd.)",
			Invisibility:     Redundant,
			PinnedBy:         []string{"us005.pub.0015"},
			InvisibilityNote: "DOWNGRADED after independent audit. 0015's own first byte is framing-invalid (RSV1+RSV3, reserved opcode 0xd), so 0015 already pins that the state refusal outranks a framing rejection. Identical all-zero STATE_VIOLATION observable.",
		},
		{
			ID: "xd.b7.closing-nonempty", Class: ClassClosedBytes, Origin: OriginNew,
			Role: "server", InitialState: "closing",
			Chunks:           [][]byte{validHi()},
			Rationale:        "non-empty valid frame in CLOSING rather than CLOSED: CLOSING counts the bytes and decodes the frame (8/8, frames=1) before raising STATE_VIOLATION, where CLOSED refuses at 0/0. Note this is ALREADY pinned by us005.pub.0051; see InvisibilityNote.",
			Invisibility:     Redundant,
			PinnedBy:         []string{"us005.pub.0051"},
			InvisibilityNote: "WITHDRAWN CLAIM. state-frame-in-closing 0051 already pins a valid non-close frame in CLOSING at consumed=9/input=9/frames=1 with STATE_VIOLATION and final_state=closing, and the evaluator compares the whole counts map exactly. Collapsing CLOSING into the CLOSED guard WOULD be caught by 0051. The prior round asserted the opposite.",
		},

		// ---- new: class D, empty-chunk handling ----
		{
			ID: "xd.d4.closing-empty-twice", Class: ClassEmptyChunk, Origin: OriginNew,
			Role: "server", InitialState: "closing",
			Chunks:           [][]byte{{}, {}},
			Rationale:        "repeated empty chunks in CLOSING, the CLOSING analogue of xd.d3.",
			Invisibility:     PartiallyInvisible,
			PinnedBy:         []string{"us005.pub.0017", "us005.pub.0045"},
			InvisibilityNote: "DOWNGRADED after independent audit. Equals xd.d1 plus xd.d3, adding nothing beyond those two already-marginal increments.",
		},
		{
			ID: "xd.d5.open-empty-then-frame", Class: ClassEmptyChunk, Origin: OriginNew,
			Role: "server", InitialState: "open",
			Chunks:           [][]byte{{}, validHi()},
			Rationale:        "empty chunk then a valid frame in OPEN: the no-op must leave the subsequent frame's accounting untouched.",
			Invisibility:     PartiallyInvisible,
			PinnedBy:         []string{"us005.pub.0006", "us005.pub.0045"},
			InvisibilityNote: "DOWNGRADED after independent audit. 0045 pins the no-op and 0006 pins a masked text frame in OPEN; because the no-op holds no decoder state, the composition is thin.",
		},
		{
			ID: "xd.d6.open-empty-between-frame-halves", Class: ClassEmptyChunk, Origin: OriginNew,
			Role: "server", InitialState: "open",
			Chunks:           [][]byte{validHi()[:4], {}, validHi()[4:]},
			Rationale:        "cross-class: an empty chunk interposed between the two halves of a split frame. If the empty no-op perturbed the reassembly offset, only this shape would show it.",
			Invisibility:     PartiallyInvisible,
			PinnedBy:         []string{"us005.pub.0024", "us005.pub.0045", "us005.pub.0072"},
			InvisibilityNote: "DOWNGRADED after independent audit, though it is the strongest of class D: the only probe delivering a zero-length chunk WHILE carry state exists. 0072/0024 pin split-frame reassembly and 0045 pins the no-op, but never together.",
		},
		{
			ID: "xd.d7.open-empty-then-rsv-midchunk", Class: ClassEmptyChunk, Origin: OriginNew,
			Role: "server", InitialState: "open",
			Chunks:           [][]byte{{}, concat(validHi(), rsv2Frame(), validOk())},
			Rationale:        "cross-class: an empty no-op immediately before the xd.a1 shape, so a no-op that silently shifted the per-site consumed base would diverge here.",
			Invisibility:     GenuinelyInvisible,
			PinnedBy:         nil,
			InvisibilityNote: "Cross-class: an empty no-op immediately before the xd.a1 shape. No public case combines a zero-length chunk with a mid-chunk rejection.",
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
