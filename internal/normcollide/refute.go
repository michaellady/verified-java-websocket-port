package normcollide

// Refutation probes: candidates decided by RUNNING them and finding that the
// projection DOES represent the distinction.
//
// A REFUTED verdict is a real result and is deliberately as hard to earn here
// as a CONFIRMED one. Two ways a lazy refutation could sneak through, both
// closed by CheckExpectation:
//
//   - the pair moves, but on a path that has nothing to do with the
//     candidate's distinction (RequiredPaths closes that);
//   - the pair moves because one of the two inputs was REJECTED, so the
//     answers differ by outcome rather than by the distinction being
//     represented (the non-error check closes that).
//
// The second one is not hypothetical for CAND-WIREBYTES: an RFC-strict codec
// rejects a non-minimal extended length, and such a codec would produce a
// moving comparator for exactly the wrong reason. The probe therefore requires
// BOTH answers to be ok rows carrying frames[].

// nonMinimalTextFrame builds one masked, FIN, text frame carrying payload
// under the 126 EXTENDED length form, whatever the payload's size. For a
// payload short enough for the 7-bit form this is a NON-MINIMAL encoding:
// RFC 6455 5.2 says the minimal form must be used, and an RFC-strict codec
// rejects it. ws-core deliberately accepts it (framing.rs strips the Codex
// codec's non-canonical-length rejection because the pinned Java runtime
// accepts non-minimal extended lengths, derive.go:400-420).
//
// Paired with maskedTextFrame over the SAME payload and the SAME mask key,
// the two differ on the wire in exactly two octets of header length and in
// nothing else — which is what makes the pair a measurement of the length
// encoding rather than of anything that happens to travel with it.
func nonMinimalTextFrame(payload []byte, key [4]byte) []byte {
	frame := []byte{0x81, 0x80 | 126, byte(len(payload) >> 8), byte(len(payload))}
	frame = append(frame, key[:]...)
	for i, b := range payload {
		frame = append(frame, b^key[i%4])
	}
	return frame
}

// Refutations is the catalog of probes whose EXPECTED verdict is REFUTED:
// distinctions the audit's first pass listed as open candidates and that a run
// shows the observation does carry.
//
// These are kept OUT of Probes() on purpose. Probes() is the confirmed-
// collision catalog, and its live gate fails on any REFUTED member; folding a
// deliberately-refuted probe into it would have meant relaxing that gate,
// which is the one move this package is not allowed to make. The two lists are
// decided by the SAME Decide function against the SAME comparator — only the
// declared expectation differs.
//
// If one of these ever comes out CONFIRMED, that is an EIGHTH collision and a
// finding, not a broken test.
func Refutations() []Probe {
	key := [4]byte{0x01, 0x02, 0x03, 0x04}
	minimal := maskedTextFrame([]byte("hi"), key)
	return []Probe{
		{
			ID:         "NC-10",
			Expect:     Refuted,
			Projection: "behaviour.ok",
			Erases: "NOTHING — this probe measures the CAND-WIREBYTES candidate and finds it " +
				"represented. The distinction is a non-minimal frame length encoding: the same " +
				"two-octet payload under the 7-bit length form and under the 126 extended form.",
			Mechanism: "frames[].wire_bytes is the CONSUMED SPAN, not a recomputed minimum: " +
				"core_adapter.rs:1398 copies frame.wire_bytes straight through, and ws-core sets " +
				"it from the span it actually ate (connection.rs `frame.wire_bytes = span.size`). " +
				"The two extra header octets therefore land in the row. counts.consumed_bytes, " +
				"counts.input_bytes and events[].bytes move with it.",
			Disclosure: "The ACCEPTANCE of non-minimal lengths is disclosed, and unusually well: " +
				"framing.rs's module header records that the Codex codec's non-canonical 16/64-bit " +
				"length rejection was STRIPPED for Java fidelity. That the resulting difference is " +
				"OBSERVABLE in the normalized row was not stated; this probe measures it.",
			Active: true,
			CollisionA: Seed{ID: "nc10.col.a", Role: "server", Steps: []map[string]any{
				bytesStep(minimal)}},
			CollisionB: Seed{ID: "nc10.col.b", Role: "server", Steps: []map[string]any{
				bytesStep(nonMinimalTextFrame([]byte("hi"), key))}},
			WireWitness: "818201020304696b (8 octets, 7-bit length form) versus " +
				"81fe000201020304696b (10 octets, 126 extended form) — identical opcode, " +
				"identical mask key, identical masked payload octets, differing only in the " +
				"length encoding",
			RequiredPaths: []string{"frames[0].wire_bytes"},
		},
		{
			ID:         "NC-11",
			Expect:     Refuted,
			Projection: "behaviour.ok",
			Erases: "NOTHING — this probe measures the CAND-CHUNKING candidate and finds it " +
				"represented. The distinction is how one frame's octets were split across input " +
				"steps: one 8-octet chunk versus two 4-octet chunks carrying the same frame.",
			Mechanism: "observe.rs emits one `input_chunk` event per surviving bytes step, " +
				"carrying that step's own byte count, and every event and frame carries the " +
				"`step` index it belongs to. A 4+4 split therefore produces THREE events where " +
				"the single chunk produces two, and the delivered text lands on step 1 rather " +
				"than step 0.",
			Disclosure: "Disclosed by construction — the event's documented shape is " +
				"`input_chunk` with `{bytes}`, one per surviving bytes step. The audit reasoned " +
				"this was represented and listed it anyway because a reasoned negative is not a " +
				"measured one. This is the measurement.",
			Active: true,
			CollisionA: Seed{ID: "nc11.col.a", Role: "server", Steps: []map[string]any{
				bytesStep(minimal)}},
			CollisionB: Seed{ID: "nc11.col.b", Role: "server", Steps: []map[string]any{
				bytesStep(minimal[:4]), bytesStep(minimal[4:])}},
			WireWitness: "the same eight octets 818201020304696b, delivered as one step and as " +
				"two four-octet steps — the same frame either way",
			RequiredPaths: []string{"events.length"},
		},
	}
}

// DecidedCandidate is a candidate the first pass left open and that a later
// run closed. It carries the ORIGINAL reason it was open, so the record shows
// what changed rather than quietly replacing it.
//
// Status is deliberately NOT authored here. Build reads it off whatever
// DecidedBy names — a probe verdict or the premise check — so a candidate
// cannot claim a decision its evidence does not carry, and a candidate whose
// DecidedBy names nothing that ran comes out with an empty status and fails
// CheckDecidedCandidates.
type DecidedCandidate struct {
	// ID is the candidate's stable identifier, unchanged from the first pass.
	ID string `json:"id"`
	// Distinction is what the wire carries, unchanged from the first pass.
	Distinction string `json:"distinction"`
	// WhyItWasOpen is the first pass's own reason, preserved verbatim.
	WhyItWasOpen string `json:"why_it_was_open"`
	// DecidedBy names the probe ID or the premise-check ID that decided it.
	DecidedBy string `json:"decided_by"`
	// Consequence says what the decision does to the headline ceilings.
	Consequence string `json:"consequence"`
	// Status is RECOMPUTED by Build from DecidedBy's result.
	Status string `json:"status"`
}

// Statuses a decided candidate can carry. There is no "PROBABLY".
const (
	// StatusRefuted means a run showed the projection represents the
	// distinction: the candidate was never a collision.
	StatusRefuted = "REFUTED"
	// StatusEmpty means no pair exists to be a collision — the candidate
	// class is empty because the code cannot produce two inputs that map
	// together. This is stronger than REFUTED and weaker in exactly one
	// way: it rests on premises about a total function, so it must carry
	// premise checks that fail when those premises change.
	StatusEmpty = "EMPTY"
	// StatusHypothesis is the undecided label, and is what a decided
	// candidate FALLS BACK TO if its evidence stops holding.
	StatusHypothesis = "HYPOTHESIS"
)

// DecidedCandidates is the closed list. It is separate from Candidates(),
// which stays the undecided list its doc comment says it is.
func DecidedCandidates() []DecidedCandidate {
	return []DecidedCandidate{
		{
			ID: "CAND-UTF8",
			Distinction: "Two different inbound octet sequences that decode to the same text, " +
				"since the `text` event records the decoded String and utf8_bytes = len(String), " +
				"never the received octets.",
			WhyItWasOpen: "Not run. Whether such a pair EXISTS depends on whether ws_core " +
				"replaces malformed UTF-8 with U+FFFD or rejects the frame; if it rejects, there " +
				"is no pair and the candidate is empty. Deciding it needs a seed per " +
				"malformed-input class, which this pass did not build.",
			DecidedBy: Utf8PremiseCheckID,
			Consequence: "EMPTY, so neither ceiling can be blamed on UTF-8 decoding. The decode " +
				"is strict, so a text event's decoded String is a total injection of the accepted " +
				"octets and an unaccepted sequence produces no text event at all. This removes " +
				"one candidate explanation for the 73-of-74 and 26-of-49 shortfalls; it does not " +
				"move either number, because both shortfalls are already attributed to CONFIRMED " +
				"probes.",
		},
		{
			ID: "CAND-WIREBYTES",
			Distinction: "Non-minimal frame length encoding: a short payload sent under the " +
				"126 extended-length form.",
			WhyItWasOpen: "Not run. frames[].wire_bytes is a total, so a non-minimal encoding " +
				"changes it and the distinction MAY be represented — which would make this a " +
				"REFUTED candidate rather than a collision. Untested either way.",
			DecidedBy: "NC-10",
			Consequence: "REFUTED on behaviour.ok: the row moves on frames[0].wire_bytes, " +
				"counts.consumed_bytes, counts.input_bytes and events[0].bytes, and BOTH answers " +
				"are ok rows, so the movement is representation and not rejection. Two public " +
				"rows differing only in length encoding would therefore be distinguishable, and " +
				"the 73-of-74 shortfall cannot be attributed to this. NOT refuted on " +
				"behaviour.failure, where frames[] is absent entirely — a rejected frame's length " +
				"encoding is erased by NC-01's mechanism, which already owns that class.",
		},
		{
			ID:          "CAND-CHUNKING",
			Distinction: "How input octets were split across steps.",
			WhyItWasOpen: "Reasoned to be REPRESENTED (input_chunk events carry a per-step " +
				"bytes count, so a 1+1 split and a 2 split differ in the events array) but not " +
				"run. Listed because a reasoned negative is still not a measured one.",
			DecidedBy: "NC-11",
			Consequence: "REFUTED on behaviour.ok, and the run says more than the reasoning did: " +
				"the pair moves on events.length (two events versus three) AND on frames[0].step " +
				"and events[1], because the step index the delivery lands on moves with the " +
				"split. The 73-of-74 shortfall cannot be attributed to chunking. NOT refuted on " +
				"behaviour.failure, where events[] is absent entirely.",
		},
	}
}

// AssignDecidedCandidateStatuses reads each decided candidate's status off
// whatever decided it and returns the populated list. It is the one place a
// candidate acquires a verdict, and it acquires it from a MEASUREMENT: a probe
// verdict out of `verdicts`, or the emptiness record's own recomputed status.
// A DecidedBy that names neither leaves the status empty, which
// CheckDecidedCandidates then refuses.
//
// This is exported, and separate from Build, for the reason PartitionCensus is:
// a check that lives only inside Build has NO coverage in the default suite,
// because Build needs a harness binary. A deletion attack on the in-Build
// version came back GREEN — nothing failed when the recomputation was replaced
// by a hardcoded EMPTY — which is exactly the finding that moved it out here.
//
// The mapping from a probe verdict to a candidate status is not the identity.
// A refutation probe coming back REFUTED closes its candidate as REFUTED; the
// same probe coming back CONFIRMED means the projection erases the distinction
// after all, so the candidate is NOT closed as confirmed here — it falls back
// to HYPOTHESIS, and the eighth-collision finding is raised by
// CheckExpectation, which is where a new collision belongs.
func AssignDecidedCandidateStatuses(decided []DecidedCandidate, verdicts map[string]Verdict,
	emptiness Utf8Emptiness) []DecidedCandidate {
	out := append([]DecidedCandidate(nil), decided...)
	for i := range out {
		candidate := &out[i]
		if emptiness.ID != "" && candidate.DecidedBy == emptiness.ID {
			candidate.Status = emptiness.Status
			continue
		}
		switch verdicts[candidate.DecidedBy] {
		case Refuted:
			candidate.Status = StatusRefuted
		case Confirmed:
			candidate.Status = StatusHypothesis
		}
	}
	return out
}

// CheckDecidedCandidates requires every decided candidate to carry a status
// that came from a run. An empty status means DecidedBy named a probe or check
// that is not in this document, so nothing decided it and the entry is a claim
// rather than a result.
func CheckDecidedCandidates(decided []DecidedCandidate) error {
	for _, candidate := range decided {
		// One membership test, two messages. It was two switch CASES until a
		// deletion attack could not neuter the empty-status one without
		// introducing a duplicate case and breaking the build — and a
		// mutation that breaks compilation proves nothing. Folded into a
		// single case list, the guard can be attacked by widening that list,
		// which is what A9 and A10 now do.
		switch candidate.Status {
		case StatusRefuted, StatusEmpty, StatusHypothesis:
		default:
			if candidate.Status == "" {
				return &decidedCandidateError{candidate.ID, candidate.DecidedBy,
					"carries no status: its decided_by names nothing that ran in this document"}
			}
			return &decidedCandidateError{candidate.ID, candidate.DecidedBy,
				"carries status " + candidate.Status + ", which is not a decision this audit issues"}
		}
		if candidate.DecidedBy == "" {
			return &decidedCandidateError{candidate.ID, "", "names nothing that decided it"}
		}
		if candidate.WhyItWasOpen == "" {
			return &decidedCandidateError{candidate.ID, candidate.DecidedBy,
				"does not preserve why it was open, so the record hides what changed"}
		}
		if candidate.Consequence == "" {
			return &decidedCandidateError{candidate.ID, candidate.DecidedBy,
				"does not say what the decision does to the headline ceilings"}
		}
	}
	return nil
}

type decidedCandidateError struct {
	id, decidedBy, problem string
}

func (e *decidedCandidateError) Error() string {
	if e.decidedBy == "" {
		return "decided candidate " + e.id + " " + e.problem
	}
	return "decided candidate " + e.id + " (decided_by " + e.decidedBy + ") " + e.problem
}
