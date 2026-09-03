package normcollide

import (
	"encoding/base64"
	"fmt"

	"github.com/michaellady/verified-java-websocket-port/internal/corpora"
)

// behaviourProtocol and handshakeProtocol are the two protocol pins the
// harness dispatches on.
const (
	behaviourProtocol = "java-websocket-oracle"
	handshakeProtocol = "java-websocket-handshake-oracle"
	protocolVersion   = "1.0.0"
)

// Seed is one oracle request line, generated from this table and never
// hand-edited, so every request_digest is recomputed rather than trusted.
//
// Exactly one of Steps (behaviour) or RawHandshake (handshake) is set; a
// RawLine seed bypasses both and is emitted verbatim, which is how the
// envelope-error projection is reached at all.
type Seed struct {
	// ID becomes request_id (behaviour) or case_id (handshake).
	ID string `json:"id"`
	// Steps is the behaviour-protocol step list.
	Steps []map[string]any `json:"steps,omitempty"`
	// Role and InitialState default to "client" and "open".
	Role         string `json:"role,omitempty"`
	InitialState string `json:"initial_state,omitempty"`
	// MaxOutputBytes overrides the default 4194304 budget. The adapter
	// floor is 512, which is below the size of any non-trivial response,
	// so this is how the output-limit projection is reached.
	MaxOutputBytes int64 `json:"max_output_bytes,omitempty"`
	// RawHandshake is the handshake-protocol payload, as literal octets.
	RawHandshake []byte `json:"-"`
	// Direction is the handshake direction.
	Direction string `json:"direction,omitempty"`
	// ClientKey is the handshake context's client_key. It is REQUIRED for a
	// server_response case (ClientHandshake::for_recorded_key consumes it)
	// and absent for a client_request one. Dropping it silently changes the
	// judged observable, which is why it is carried rather than defaulted.
	ClientKey string `json:"client_key,omitempty"`
	// RawLine, when set, is emitted verbatim as the request line.
	RawLine string `json:"raw_line,omitempty"`
}

// Line renders the seed as one canonical JSONL request line with a
// recomputed digest binding.
func (s Seed) Line() (string, error) {
	if s.RawLine != "" {
		return s.RawLine, nil
	}
	var request map[string]any
	switch {
	case s.RawHandshake != nil:
		context := map[string]any{}
		if s.ClientKey != "" {
			context["client_key"] = s.ClientKey
		}
		request = map[string]any{
			"case_id":    s.ID,
			"config":     map[string]any{"max_handshake_bytes": 4096, "max_header_count": 32, "max_header_line_bytes": 512},
			"context":    context,
			"direction":  s.Direction,
			"protocol":   handshakeProtocol,
			"raw_base64": base64.StdEncoding.EncodeToString(s.RawHandshake),
			"version":    protocolVersion,
		}
	case s.Steps != nil:
		role, initial := s.Role, s.InitialState
		if role == "" {
			role = "client"
		}
		if initial == "" {
			initial = "open"
		}
		output := s.MaxOutputBytes
		if output == 0 {
			output = 4194304
		}
		steps := make([]any, len(s.Steps))
		for i, step := range s.Steps {
			steps[i] = step
		}
		request = map[string]any{
			"initial_state": initial,
			"limits": map[string]any{
				"max_actions": 64, "max_buffered_bytes": 65536, "max_frames": 64,
				"max_input_bytes": 65536, "max_output_bytes": output,
			},
			"protocol":   behaviourProtocol,
			"request_id": s.ID,
			"role":       role,
			"steps":      steps,
			"version":    protocolVersion,
		}
	default:
		return "", fmt.Errorf("seed %s sets neither Steps, RawHandshake nor RawLine", s.ID)
	}
	unsigned, err := corpora.CanonicalJSON(request)
	if err != nil {
		return "", err
	}
	request["request_digest"] = corpora.DigestSHA256(unsigned)
	line, err := corpora.CanonicalJSON(request)
	if err != nil {
		return "", err
	}
	return string(line), nil
}

// Probe is one decided candidate. The Collision pair is the claim; the
// Witness pair (or WireWitness) is what makes the claim falsifiable.
type Probe struct {
	// ID is the stable probe identifier.
	ID string `json:"id"`
	// Expect is the verdict the catalog CLAIMS this probe has. It is
	// declared here and compared against the run by CheckExpectation, so a
	// probe that stops behaving as catalogued is a loud failure rather
	// than a silently reclassified entry. Probes() members declare
	// CONFIRMED; Refutations() members declare REFUTED.
	Expect Verdict `json:"expected_verdict"`
	// Projection names the surface entry the probe exercises.
	Projection string `json:"projection"`
	// Erases states, in one sentence, what distinction is destroyed.
	Erases string `json:"erases"`
	// Mechanism names the code site that destroys it.
	Mechanism string `json:"mechanism"`
	// Disclosure records whether the project already documented this
	// erasure, and where. A collision the tree already discloses is still
	// a collision, but it is not a discovery and must not be reported as
	// one.
	Disclosure string `json:"disclosure"`
	// Active says whether the CURRENT scored corpora actually contain rows
	// of this projection. A confirmed collision on a projection no row
	// reaches bounds future corpora, not today's headline number, and
	// saying otherwise would overstate it.
	Active bool `json:"active_in_scored_corpora"`
	// CollisionA and CollisionB are the two genuinely different behaviours
	// the projection maps together.
	CollisionA Seed `json:"collision_a"`
	CollisionB Seed `json:"collision_b"`
	// WitnessA and WitnessB carry the SAME distinction into a projection
	// that does represent it. When they are set, the decision requires the
	// comparator to MOVE on them: that is what proves the two collision
	// behaviours really are different rather than accidentally equal.
	WitnessA *Seed `json:"witness_a,omitempty"`
	WitnessB *Seed `json:"witness_b,omitempty"`
	// WireWitness is the alternative for distinctions NO projection can
	// represent, where a witness pair is impossible by construction. The
	// decision then requires the two seeds' own request lines to differ,
	// which proves the inputs are distinct octet sequences.
	WireWitness string `json:"wire_witness,omitempty"`
	// RequiredPaths belongs to a REFUTED-expecting probe and names the
	// comparator paths that MUST have moved for the refutation to count. A
	// refutation whose pair moved on something unrelated has decided
	// nothing, and CheckExpectation refuses it. A CONFIRMED-expecting probe
	// must leave this empty: it cannot both erase a distinction and be
	// required to move on it.
	RequiredPaths []string `json:"required_diff_paths,omitempty"`
}

func textStep(text string) map[string]any {
	return map[string]any{"action": "send_text", "kind": "action", "text": text}
}

func closeStep(code int64, reason string) map[string]any {
	return map[string]any{"action": "send_close", "code": code, "kind": "action", "reason": reason}
}

func bytesStep(raw []byte) map[string]any {
	return map[string]any{"data_base64": base64.StdEncoding.EncodeToString(raw), "kind": "bytes"}
}

// maskedTextFrame builds one masked, FIN, text frame carrying payload under
// the given four-octet mask key. Two calls with the same payload and
// different keys produce DIFFERENT octets on the wire and the SAME semantic
// frame, which is exactly the NC-03 distinction.
func maskedTextFrame(payload []byte, key [4]byte) []byte {
	frame := []byte{0x81, byte(0x80 | len(payload))}
	frame = append(frame, key[:]...)
	for i, b := range payload {
		frame = append(frame, b^key[i%4])
	}
	return frame
}

// fragmentStartFrame is maskedTextFrame with FIN cleared: the same payload
// under the same key, differing from it in exactly the bit NC-04 says the
// error projection erases. Feeding both as ACCEPTED frames is the witness.
func fragmentStartFrame(payload []byte, key [4]byte) []byte {
	frame := maskedTextFrame(payload, key)
	frame[0] &^= 0x80
	return frame
}

func upgradeRequest(path, host, key, extra string) []byte {
	return []byte("GET " + path + " HTTP/1.1\r\nHost: " + host +
		"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n" + extra + "\r\n")
}

// truncateTerminator drops the final CRLF, leaving a handshake that is
// complete in every header but has never been terminated — the canonical
// `incomplete`. Computed from the request's own length rather than sliced at
// a guessed offset.
func truncateTerminator(request []byte) []byte {
	return request[:len(request)-2]
}

const recordedKey = "7Qg8Jw3qQL4ERr/n83YN7w=="

// The two shipped public scenarios whose scored rows are identical. These are
// not synthesized: they are copied from corpora/public/scenarios.jsonl, and
// TestCorpusCollisionSeedsMatchTheShippedScenarios re-reads that file and
// fails if either step ever changes.
const (
	pub0039Frame = "gIMcm8rf/vVB" // 80 83 1c 9b ca df fe f5 41 — FIN=1, opcode 0
	pub0066Frame = "AIMdOb7brW1E" // 00 83 1d 39 be db ad 6d 44 — FIN=0, opcode 0
)

func rawBytesStep(dataBase64 string) map[string]any {
	return map[string]any{"data_base64": dataBase64, "kind": "bytes"}
}

// Probes is the decided catalog. Every entry here has been RUN; the verdicts
// live in the committed document and are recomputed by Verify.
func Probes() []Probe {
	badClose := closeStep(999, "bad")
	return []Probe{
		{
			ID:         "NC-01",
			Expect:     Confirmed,
			Projection: "behaviour.failure",
			Erases: "Any difference in what the connection actually did before it failed: " +
				"a differing outbound payload, a differing frame, a differing transition, " +
				"a differing close detail. An error row carries none of them.",
			Mechanism: "failure_response emits only base+error+counts+final_state+runtime, " +
				"mirroring OracleEngine.failure. EvaluateOracleResponse's error branch then " +
				"compares only error.code, error.close_code, final_state and counts — and " +
				"error.detail is excused by diffregress as non-semantic (DetailField).",
			Disclosure: "The DROP is disclosed (failure_response's doc comment says the failure " +
				"envelope retains only counts and final state). The CONSEQUENCE — that this makes " +
				"26 of the 74 public rows blind to every observation stream — is not stated anywhere " +
				"in the tree that this audit found.",
			Active:     true,
			CollisionA: Seed{ID: "nc01.col.a", Steps: []map[string]any{textStep("AA"), badClose}},
			CollisionB: Seed{ID: "nc01.col.b", Steps: []map[string]any{textStep("BB"), badClose}},
			WitnessA:   &Seed{ID: "nc01.wit.a", Steps: []map[string]any{textStep("AA")}},
			WitnessB:   &Seed{ID: "nc01.wit.b", Steps: []map[string]any{textStep("BB")}},
		},
		{
			ID:         "NC-02",
			Expect:     Confirmed,
			Projection: "behaviour.output_limit",
			Erases: "EVERYTHING the request produced, plus the responder's own identity. " +
				"Two behaviours that differ in final_state, in close, in transitions and in " +
				"every event collapse to the same six keys with a constant detail string.",
			Mechanism: "output_limit_response emits base+error{code,detail} only, mirroring " +
				"Execution.failure(minimal=true). Because `runtime` is absent, a Java row and a " +
				"Rust row for the same request are BYTE-IDENTICAL.",
			Disclosure: "The drop is disclosed in output_limit_response's doc comment, which " +
				"lists runtime among the omissions. The consequence for the differential is not.",
			Active: false,
			CollisionA: Seed{ID: "nc02.col.a", MaxOutputBytes: 512,
				Steps: []map[string]any{textStep("AAAA")}},
			CollisionB: Seed{ID: "nc02.col.b", MaxOutputBytes: 512,
				Steps: []map[string]any{closeStep(1000, "z")}},
			WitnessA: &Seed{ID: "nc02.wit.a", Steps: []map[string]any{textStep("AAAA")}},
			WitnessB: &Seed{ID: "nc02.wit.b", Steps: []map[string]any{closeStep(1000, "z")}},
		},
		{
			ID:         "NC-03",
			Expect:     Confirmed,
			Projection: "behaviour.ok",
			Erases:     "The four-octet frame mask key of every inbound frame.",
			Mechanism: "FrameRecord has no mask-key member at all (observe.rs: \"Client mask keys " +
				"are deliberately absent (quirk Q28): frames are observed semantically, with " +
				"unmasked payloads\"). No projection can represent it, so no witness pair exists.",
			Disclosure: "DISCLOSED as quirk Q28 in observe.rs. This probe adds only the " +
				"constructive proof that two different wire octet sequences really do produce " +
				"identical rows.",
			Active: true,
			CollisionA: Seed{ID: "nc03.col.a", Role: "server", Steps: []map[string]any{
				bytesStep(maskedTextFrame([]byte("hi"), [4]byte{0x01, 0x02, 0x03, 0x04}))}},
			CollisionB: Seed{ID: "nc03.col.b", Role: "server", Steps: []map[string]any{
				bytesStep(maskedTextFrame([]byte("hi"), [4]byte{0xAA, 0xBB, 0xCC, 0xDD}))}},
			WireWitness: "the two bytes steps carry 818201020304696b and 8182aabbccddc2d2 — " +
				"eight octets each, differing in six of them",
		},
		{
			ID:         "NC-04",
			Expect:     Confirmed,
			Projection: "behaviour.failure",
			Erases: "The FIN bit of a rejected frame. This probe is NOT synthesized: its two " +
				"seeds are the shipped steps of us005.pub.0039 and us005.pub.0066, two of the " +
				"seventy-four public scenarios. Their frames differ in the FIN bit (0x80 versus " +
				"0x00) and in every payload octet, both are rejected as \"Continuous frame " +
				"sequence was not started\", and their scored rows are IDENTICAL.",
			Mechanism: "Same as NC-01 — failure_response emits no frames[] — but instantiated " +
				"inside the corpus the 74/74 is computed over, so it costs the headline number a " +
				"row rather than bounding a hypothetical one.",
			Disclosure: "NOT DISCLOSED. Nothing this audit found records that two of the 74 " +
				"public scenarios are indistinguishable to the differential.",
			Active:     true,
			CollisionA: Seed{ID: "us005.pub.0039", Steps: []map[string]any{rawBytesStep(pub0039Frame)}},
			CollisionB: Seed{ID: "us005.pub.0066", Steps: []map[string]any{rawBytesStep(pub0066Frame)}},
			// The witness feeds the SAME FIN distinction on a frame that is
			// accepted, where frames[].fin is a real member and moves.
			WitnessA: &Seed{ID: "nc04.wit.a", Role: "server", Steps: []map[string]any{
				bytesStep(maskedTextFrame([]byte("hi"), [4]byte{0x01, 0x02, 0x03, 0x04}))}},
			WitnessB: &Seed{ID: "nc04.wit.b", Role: "server", Steps: []map[string]any{
				bytesStep(fragmentStartFrame([]byte("hi"), [4]byte{0x01, 0x02, 0x03, 0x04}))}},
		},
		{
			ID:         "NC-07",
			Expect:     Confirmed,
			Projection: "handshake.judged",
			Erases: "The entire HTTP request head apart from the key: path, Host, and — the " +
				"part that matters most — Sec-WebSocket-Protocol and Sec-WebSocket-Extensions. " +
				"Subprotocol and extension negotiation is unobservable to the 49-case exam.",
			Mechanism: "handshake_adapter.rs::judge discards the response head by its own " +
				"admission (\"never the response head, which it discards below\") and respond() " +
				"emits only java_observable plus sec_websocket_accept on a server-side accept.",
			Disclosure: "The head-discard is disclosed in the adapter's own comment, scoped to " +
				"the RESPONSE head. That the REQUEST's negotiation headers are equally unscored " +
				"is not stated, and permessage-deflate is precisely the kind of behaviour a port " +
				"could get wrong.",
			Active: true,
			CollisionA: Seed{ID: "nc07.col.a", Direction: "client_request",
				RawHandshake: upgradeRequest("/socket/aaaa", "host-a.example", recordedKey, "")},
			CollisionB: Seed{ID: "nc07.col.b", Direction: "client_request",
				RawHandshake: upgradeRequest("/totally/different/path", "host-zzzzzzzz.example", recordedKey,
					"Sec-WebSocket-Protocol: chat\r\nSec-WebSocket-Extensions: permessage-deflate\r\n")},
			WireWitness: "164 request octets versus 258, differing in path, Host, and two whole " +
				"negotiation headers the observation vocabulary has no member for",
		},
		{
			ID:         "NC-08",
			Expect:     Confirmed,
			Projection: "handshake.judged",
			Erases: "Everything about an incomplete handshake: how many octets arrived, which " +
				"headers had been seen, where the parser stopped.",
			Mechanism: "Observable::Incomplete carries no payload, so respond() emits the bare " +
				"literal \"incomplete\" and nothing else.",
			Disclosure: "NOT DISCLOSED anywhere this audit found.",
			Active:     true,
			CollisionA: Seed{ID: "nc08.col.a", Direction: "client_request",
				RawHandshake: []byte("GET / HTTP/1.1\r\n")},
			CollisionB: Seed{ID: "nc08.col.b", Direction: "client_request",
				RawHandshake: truncateTerminator(upgradeRequest("/x", "h.example", recordedKey, ""))},
			WireWitness: "16 octets versus a whole upgrade request one CRLF short of complete — " +
				"and the observation is the same single word. NOTE: an earlier version of this " +
				"probe truncated with a fixed [:160] slice that did not actually cut the shorter " +
				"request, so collision B was a COMPLETE handshake and the run REFUTED the probe " +
				"(collision_diff_paths = [java_observable sec_websocket_accept]). The refutation " +
				"was correct and is why the truncation is now computed rather than guessed.",
		},
		{
			ID:         "NC-09",
			Expect:     Confirmed,
			Projection: "handshake.judged",
			Erases: "Every distinction between two rejected handshakes that take the same " +
				"draft-API channel — including the Sec-WebSocket-Key, which is never echoed on " +
				"a reject. close_code is a CONSTANT (HANDSHAKE_REJECT_CLOSE_CODE) and carries " +
				"no information at all.",
			Mechanism: "respond() emits reject_channel plus a hardcoded 1002. " +
				"evaluateHandshakeLiveResponse compares exactly those two.",
			Disclosure: "DISCLOSED, and unusually well: evidence/us005-handshake-live-mapping.json's " +
				"granularity_statement says the Java runtime cannot observably distinguish most " +
				"HS_* reject codes and that the draft-API channel is \"the finest honest " +
				"granularity\". This probe measures the size of the resulting classes.",
			Active: true,
			CollisionA: Seed{ID: "nc09.col.a", Direction: "client_request",
				RawHandshake: []byte("GET /a HTTP/1.1\r\nHost: a.example\r\nUpgrade: websocket\r\n" +
					"Connection: Upgrade\r\nSec-WebSocket-Key: " + recordedKey + "\r\n\r\n")},
			CollisionB: Seed{ID: "nc09.col.b", Direction: "client_request",
				RawHandshake: []byte("GET /completely/other HTTP/1.1\r\nHost: zzzzzz.example\r\n" +
					"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
					"Sec-WebSocket-Key: ELk6s4dWP8nDk6qRlvVz3A==\r\nX-Pad: 12345\r\n\r\n")},
			WireWitness: "different path, different Host, DIFFERENT Sec-WebSocket-Key, and an " +
				"extra header — one identical scored row",
		},
	}
}

// Candidate is a distinction this audit reasoned about but did NOT decide by
// running a seed. It is a hypothesis and is reported as one. Nothing in the
// document's confirmed-collision count includes a candidate.
type Candidate struct {
	// ID is the stable identifier.
	ID string `json:"id"`
	// Distinction is what the wire carries.
	Distinction string `json:"distinction"`
	// Why says why it was not decided by construction here.
	Why string `json:"why"`
	// Status is always "HYPOTHESIS".
	Status string `json:"status"`
}

// Candidates is the undecided list. It is part of the deliverable: an
// enumeration that hid its own loose ends would be worth less than one that
// names them.
//
// It held five entries in the first pass. Three of them — CAND-UTF8,
// CAND-WIREBYTES and CAND-CHUNKING — have since been DECIDED by running them,
// and have moved to DecidedCandidates() carrying the reason they were open
// plus the evidence that closed them. They were not deleted and they were not
// reasoned shut.
//
// The two that remain are structurally undecidable IN THIS PACKAGE, and stay
// here for that reason rather than for lack of effort: CAND-TRANSPORT needs a
// real peer socket, which no oracle-protocol step feeds or observes, and
// CAND-CROSSARRAY needs a MUTATED harness, because the shipped one generates
// all three arrays from one pass and so cannot be made to emit them in a
// different relative order. Manufacturing a decision for either would be
// exactly the move this catalogue exists to refuse.
func Candidates() []Candidate {
	return []Candidate{
		{
			ID:          "CAND-TRANSPORT",
			Distinction: "Socket lifecycle: who sends TCP FIN, when, and whether RST follows.",
			Why: "This is DIV-02's class and it is already registered in internal/ac5class. " +
				"It cannot be decided by a seed in THIS package because the oracle protocol has " +
				"no step that feeds or observes a socket — the witness has to be a real peer " +
				"socket, which is ws-testee's loopback test, not a transcript comparison. " +
				"Confirmed elsewhere, out of scope here, and listed so the surface is not " +
				"silently missing its most famous member.",
			Status: "HYPOTHESIS",
		},
		{
			ID:          "CAND-CROSSARRAY",
			Distinction: "The relative order of an event, a frame and a transition caused by the same step.",
			Why: "This is the known US-013 AC5 case (Events[] and Transitions[] are separate " +
				"arrays, internal/lab/oracle.go:315 and :325). It is NOT decided here because " +
				"the harness generates all three arrays from one pass, so no request this " +
				"package can write makes the port emit them in a different relative order — " +
				"seeding it needs a MUTATED harness, which is cmd/mutctl's instrument, not this " +
				"one. Reasoned, not run.",
			Status: "HYPOTHESIS",
		},
	}
}
