package divergencesweep

import (
	"fmt"
	"sort"
)

// Recommendation is the disposition this sweep proposes for a divergence
// class. Nothing here writes to the behavior-delta ledger: the ledger is
// append-only with a frozen prefix, so these are proposals, drafted under
// drafts/ledger-proposals/ and decided by the owner.
type Recommendation string

const (
	// RecommendFixInPort means the port should be changed to do what shipped
	// Java does, because Java's behaviour is the equivalence target.
	RecommendFixInPort Recommendation = "FIX_IN_PORT"
	// RecommendLedgerPreservedJava means the port already matches Java and
	// the divergence is from the RFC, so it is ledgered as a preserved Java
	// behaviour rather than fixed.
	RecommendLedgerPreservedJava Recommendation = "LEDGER_PRESERVED_JAVA_BEHAVIOUR"
	// RecommendLedgerIntentionalCorrection means the port deliberately does
	// something Java does not, and the difference is kept and disclosed.
	RecommendLedgerIntentionalCorrection Recommendation = "LEDGER_INTENTIONAL_CORRECTION"
	// RecommendAlreadyLedgered means an existing ledger record already
	// carries this proposition; the sweep only measures its extent.
	RecommendAlreadyLedgered Recommendation = "ALREADY_LEDGERED"
)

// Selector picks the case set a divergence class claims, per subject role, out
// of the recomputed differences. It never names a case identity directly: the
// set is whatever the report bytes produce, so a run in which the divergence
// moved produces a different set and the committed document stops matching.
type Selector struct {
	// Dimension the class is selected on.
	Dimension string
	// Verdicts that select; empty means any non-AGREE verdict.
	Verdicts []Verdict
	// PortValue and JavaValue, when non-empty, are canonical JSON encodings
	// the difference's values must equal.
	PortValue string
	JavaValue string
	// Roles the class applies to; empty means both.
	Roles []string
	// ExcludeClassIDs removes cases already claimed by an earlier class, so
	// two classes never both claim the same case on their selecting
	// dimension and the narrative stays one-cause-per-case.
	ExcludeClassIDs []string
}

// ClassSpec is one named divergence with the dimensions it explains.
type ClassSpec struct {
	ID             string
	Title          string
	Selector       Selector
	Explains       []string
	Mechanism      string
	JavaCitation   string
	PortSite       string
	Direction      string
	Recommendation Recommendation
	Why            string
	// ProposedLedgerSubjectRef is the subject_ref a drafted ledger record
	// under drafts/ledger-proposals/ would carry. It is asserted ABSENT from
	// the committed behavior-delta ledger: the day it appears, the draft has
	// landed and this sweep's recommendation is stale.
	ProposedLedgerSubjectRef string
	// ExistingLedgerSubjectRef and ExistingLedgerSequence are set only where
	// a committed ledger record already carries the proposition. They are
	// asserted PRESENT, at that sequence.
	ExistingLedgerSubjectRef string
	ExistingLedgerSequence   int
}

// Classes is the closed, ordered set of divergence classes this sweep names.
// Order matters: ExcludeClassIDs may only refer to classes declared earlier.
func Classes() []ClassSpec {
	return []ClassSpec{
		{
			ID:                       "DIV-01-fail-without-close-frame",
			ProposedLedgerSubjectRef: "semantic:org.java-websocket.websocketimpl.failure-close-frame-emission:provisional-v1",
			Title:                    "On a connection failure the port drops TCP without sending a Close frame; shipped Java sends one and completes the closing handshake",
			Selector: Selector{
				Dimension: "subject_close_code",
				Verdicts:  []Verdict{VerdictPortAbsent},
			},
			Explains: []string{
				"subject_close_code",
				"subject_close_reason",
				"suite_close_code",
				"close_was_clean",
				"not_clean_reason",
				"close_verdict_text",
				"behavior_close",
				"behavior_verdict_text",
				"rx_frame_stats",
				"tx_frame_stats",
				"tcp_connection_dropped_by",
				"suite_dropped_tcp",
				"received_messages",
			},
			Mechanism:      "Java answers an InvalidDataException from frame decoding by calling WebSocketImpl.close(code, message, false), which sends a CloseFrame carrying the exception's close code and its message text and only then flushes and closes the channel. The port's Autobahn adapter terminates the transport on the typed failure without composing that frame, so the suite records no close code and no close reason from the subject and scores the TCP end as a bare drop.",
			JavaCitation:   "java-v1.6.0:org.java_websocket.WebSocketImpl:close(int,String,boolean) — sendFrame(closeFrame) then flushAndClose; the code and message come from the InvalidDataException raised in org.java_websocket.drafts.Draft_6455:translateFrame/processFrame",
			PortSite:       "rust/ws-testee (the Autobahn adapter); the shipped-Java reaction is implemented on branch claude/post-failure at commit 77d8c23, which is NOT in mainline as of this sweep",
			Direction:      "port is weaker than Java: it emits strictly less on the wire",
			Recommendation: RecommendFixInPort,
			Why:            "The equivalence target is shipped Java 1.6.0, quirks included. Java's close code and reason are observable to every peer, and the distinct reason strings this run recorded are listed under this dimension's value_pairs; a peer that logs or branches on them sees a different program. The fix already exists on claude/post-failure and is queued as P2(a); this sweep measures its exact extent and gives it a per-case acceptance set.",
		},
		{
			ID:                       "DIV-02-server-leaves-tcp-open",
			ProposedLedgerSubjectRef: "semantic:org.java-websocket.websocketimpl.server-tcp-close-after-close-handshake:provisional-v1",
			Title:                    "After the closing handshake the port's server leaves the TCP connection open; shipped Java's server closes it",
			Selector: Selector{
				Dimension: "tcp_connection_dropped_by",
				Verdicts:  []Verdict{VerdictBothDiffer},
				PortValue: `"AUTOBAHN_SUITE"`,
				JavaValue: `"SUBJECT"`,
				Roles:     []string{"server"},
			},
			Explains: []string{
				"tcp_connection_dropped_by",
				"suite_dropped_tcp",
				"failed_by_suite",
				"server_connection_drop_timeout",
				"close_was_clean",
				"not_clean_reason",
				"close_verdict_text",
				"behavior_close",
			},
			Mechanism:      "Java's WebSocketImpl.flushAndClose demands a write of the pending close frame and the selector loop then calls closeConnection, which cancels the key and closes the channel, so the server end of the socket goes away without the client having to act. The port's adapter completes the WebSocket closing handshake and leaves the socket to the peer. The suite records this two ways depending on how long it waits: as a preference violation when it closes promptly, and as a drop timeout when it does not.",
			JavaCitation:   "java-v1.6.0:org.java_websocket.WebSocketImpl:flushAndClose and :closeConnection(int,String,boolean) — channel.close() on the subject side",
			PortSite:       "rust/ws-testee (the Autobahn adapter); no branch in this repository implements it as of this sweep",
			Direction:      "port is weaker than Java: it holds a socket Java releases",
			Recommendation: RecommendFixInPort,
			Why:            "RFC 6455 section 7.1.1 says the server should close the TCP connection first, and shipped Java does. Leaving it open is both a divergence from the equivalence target and a resource-holding difference a production peer would feel. This is queued as P2(b); the sweep supplies the case set and the two ways the suite scores it.",
		},
		{
			ID:                       "DIV-03-invalid-utf8-close-reason-tcp-end",
			ProposedLedgerSubjectRef: "semantic:org.java-websocket.closeframe.invalid-utf8-reason-transport-stall:provisional-v1",
			Title:                    "On a Close frame whose reason is invalid UTF-8, the port ends the TCP connection and shipped Java neither answers nor ends it",
			Selector: Selector{
				Dimension: "tcp_connection_dropped_by",
				Verdicts:  []Verdict{VerdictBothDiffer},
				PortValue: `"SUBJECT"`,
				JavaValue: `"AUTOBAHN_SUITE"`,
				Roles:     []string{"server"},
			},
			Explains: []string{
				"tcp_connection_dropped_by",
				"suite_dropped_tcp",
				"close_handshake_timeout",
				"not_clean_reason",
				"close_verdict_text",
				"behavior_close",
			},
			Mechanism:      "The suite sends a close frame whose reason bytes are not valid UTF-8. Shipped Java's CloseFrame.isValid rejects the reason at runtime and the connection is left neither answered nor closed, so the suite's own close-handshake timer expires and the SUITE drops the socket. The port ends the transport itself. This is the same port mechanism as DIV-01 seen from the other side: because the port's reaction to a failure is to drop TCP, it happens to drop where Java stalls.",
			JavaCitation:   "java-v1.6.0:org.java_websocket.framing.CloseFrame:isValid — the invalid-UTF-8 reason rejection ledgered at behavior-delta sequence 32",
			PortSite:       "rust/ws-testee (the Autobahn adapter), same site as DIV-01",
			Direction:      "port and Java differ; on this case the port is the one that terminates",
			Recommendation: RecommendFixInPort,
			Why:            "Not a separate defect and not a case to preserve: it is DIV-01's mechanism with the polarity reversed, and the same fix governs it. It is called out separately because it is the ONE case in 494 where the port ends a TCP connection Java leaves open, and a fix for DIV-01 that does not also reproduce Java's stall here would leave a divergence behind. Its acceptance criterion is therefore 'this case still differs from today's port after the DIV-01 fix' — which is why it must not be folded into DIV-01's count.",
		},
		{
			ID:                       "DIV-04-dispatch-phase-echo-enqueue",
			ExistingLedgerSubjectRef: "semantic:org.java-websocket.websocketimpl.batch-drain-echo-flush-ordering:provisional-v1",
			ExistingLedgerSequence:   34,
			Title:                    "Autobahn 5.15: Java's echo is already enqueued when the failure path flushes and the port's failure lands first",
			Selector: Selector{
				Dimension: "behavior",
				Verdicts:  []Verdict{VerdictBothDiffer},
			},
			Explains:       []string{"behavior", "received_messages", "rx_frame_stats"},
			Mechanism:      "Java's translateFrame decodes the whole chop before dispatching frame by frame, so the echo of the completed message is enqueued by the time the poisoned frame's failure path runs flushAndClose. The port's typed failure lands before the completed message's Text event is delivered, so nothing is enqueued.",
			JavaCitation:   "java-v1.6.0:org.java_websocket.WebSocketImpl:decodeFrames",
			PortSite:       "rust/ws-core dispatch ordering",
			Direction:      "the port fails before delivery where Java's echo is already enqueued; RFC 6455 7.1.7 permits both, and Autobahn scores Java OK and the port NON-STRICT",
			Recommendation: RecommendAlreadyLedgered,
			Why:            "Behavior-delta ledger sequence 34 already carries this proposition, and the committed behavior-class divergence register cites it for both roles. The sweep adds nothing to decide; it records that the close dimensions on this case do NOT diverge, which the behaviour class alone could not say.",
		},
		{
			ID:                       "DIV-05-close-overtakes-a-large-echo",
			ProposedLedgerSubjectRef: "semantic:org.java-websocket.websocketimpl.pending-echo-versus-close-ordering:provisional-v1",
			Title:                    "Autobahn 7.1.6: a close arriving during a 256 KiB echo cancels the echo in the port and does not in shipped Java",
			Selector: Selector{
				Dimension:       "received_messages",
				Verdicts:        []Verdict{VerdictBothDiffer},
				ExcludeClassIDs: []string{"DIV-04-dispatch-phase-echo-enqueue"},
			},
			Explains:       []string{"received_messages", "behavior_verdict_text", "rx_frame_stats"},
			Mechanism:      "The suite sends a 256 KiB text message, then a close, then a ping. Shipped Java returns the echo and then answers the close with 1000; the port processes the close first, the echo is never returned, and — by DIV-01's mechanism — no close frame is sent either. The suite's own verdict text names it: 'Close was processed before text message could be returned.'",
			JavaCitation:   "java-v1.6.0:org.java_websocket.WebSocketImpl:decodeFrames and :flushAndClose — the write demand flushes queued frames before the channel is closed",
			PortSite:       "rust/ws-core and rust/ws-driver write-queue drain on close",
			Direction:      "port is weaker than Java: it drops a message Java delivers",
			Recommendation: RecommendFixInPort,
			Why:            "Autobahn scores this case INFORMATIONAL for both subjects, so no scoring gate in this repository can see it, and the public corpus has no 256 KiB echo-versus-close race. Dropping an already-complete application message on close is a user-visible behaviour difference, not a strictness choice. It is a candidate defect and should be reproduced as a ws-core or ws-driver test before any fix; if reproduction shows the port cannot enqueue the echo without breaking a ledgered ordering, it becomes a ledger record instead. Recorded as FIX_IN_PORT with that reproduction as its precondition.",
		},
		{
			ID:                       "DIV-06-server-101-headers",
			ProposedLedgerSubjectRef: "semantic:org.java-websocket.draft6455.server-handshake.response-server-and-date-fields:provisional-v1",
			Title:                    "The port's 101 response omits Server and Date and does not sort its header names; shipped Java sends five headers in case-insensitive alphabetical order",
			Selector: Selector{
				Dimension: "subject_handshake_header_names",
				Verdicts:  []Verdict{VerdictBothDiffer},
				Roles:     []string{"server"},
			},
			Explains:       []string{"subject_handshake_header_names"},
			Mechanism:      "Draft_6455.postProcessHandshakeResponseAsServer puts Server: TooTallNate Java-WebSocket and Date: getServerTime() into the response after the Upgrade, Connection and Sec-WebSocket-Accept fields, and HandshakedataImpl1 stores fields in a TreeMap ordered by String.CASE_INSENSITIVE_ORDER, so the wire order is alphabetical. The port's accept_response writes exactly three fields in a fixed order and neither of the two Java adds.",
			JavaCitation:   "java-v1.6.0:org.java_websocket.drafts.Draft_6455:postProcessHandshakeResponseAsServer (lines 449-450 of the pinned source) and org.java_websocket.handshake.HandshakedataImpl1 (TreeMap with String.CASE_INSENSITIVE_ORDER)",
			PortSite:       "rust/ws-core/src/handshake/server.rs::accept_response",
			Direction:      "port is weaker than Java: it emits strictly fewer response fields",
			Recommendation: RecommendFixInPort,
			Why:            "This is on every one of the 247 server-role cases and no gate in this repository sees it: Autobahn scores the upgrade, not the response fields, and the handshake exam scores the accept/reject decision and the Sec-WebSocket-Accept value. The port's own doc comment cites postProcessHandshakeResponseAsServer as the authority for the three fields it writes, while that same method writes five — an incomplete citation of the cited method. Date carries a clock so it cannot be reproduced byte-for-byte, which is a reason to disclose the field's VALUE as non-deterministic, not a reason to omit the field.",
		},
		{
			ID:                       "DIV-07-client-request-header-order",
			ProposedLedgerSubjectRef: "semantic:org.java-websocket.handshake.field-emission-order:provisional-v1",
			Title:                    "The port's client request carries the same five header names as shipped Java in a different order",
			Selector: Selector{
				Dimension: "subject_handshake_header_names",
				Verdicts:  []Verdict{VerdictBothDiffer},
				Roles:     []string{"client"},
			},
			Explains:       []string{"subject_handshake_header_names"},
			Mechanism:      "Java builds the client handshake through the same HandshakedataImpl1 TreeMap, so its request fields go out in case-insensitive alphabetical order: Connection, Host, Sec-WebSocket-Key, Sec-WebSocket-Version, Upgrade. The port writes Host, Upgrade, Connection, Sec-WebSocket-Key, Sec-WebSocket-Version. The header SET is identical on all 247 cases; only the order differs.",
			JavaCitation:   "java-v1.6.0:org.java_websocket.handshake.HandshakedataImpl1 (TreeMap with String.CASE_INSENSITIVE_ORDER) consumed by org.java_websocket.drafts.Draft:createHandshake",
			PortSite:       "rust/ws-core client handshake request composition",
			Direction:      "port and Java differ in field order only; no field is missing on either side",
			Recommendation: RecommendLedgerIntentionalCorrection,
			Why:            "HTTP header order is not semantically significant under RFC 7230 for distinct field names, and no measured behaviour in this run depends on it: the suite accepted every one of the 247 requests. It is nonetheless an observable byte-level difference against the equivalence target, present on every case, and a peer that digests the raw request head would see it. It should be ledgered as a disclosed, deliberate ordering difference rather than either hidden or chased, unless the owner rules that byte-level handshake fidelity is in scope, in which case it becomes FIX_IN_PORT alongside DIV-06.",
		},
	}
}

// ClaimedDifference is one difference attributed to a class.
type ClaimedDifference struct {
	ClassID string
	Key     string
}

// classCases evaluates a selector against the recomputed differences.
func classCases(sweep *Sweep, spec ClassSpec, earlier map[string]map[string]map[string]bool) (map[string][]string, error) {
	roles := spec.Selector.Roles
	if len(roles) == 0 {
		roles = []string{"server", "client"}
	}
	known := map[string]bool{}
	for _, dimension := range Dimensions() {
		known[dimension.Name] = true
	}
	if !known[spec.Selector.Dimension] {
		return nil, fmt.Errorf("class %s selects on unknown dimension %q", spec.ID, spec.Selector.Dimension)
	}
	for _, dimension := range spec.Explains {
		if !known[dimension] {
			return nil, fmt.Errorf("class %s explains unknown dimension %q", spec.ID, dimension)
		}
	}
	excluded := map[string]map[string]bool{}
	for _, classID := range spec.Selector.ExcludeClassIDs {
		byRole, ok := earlier[classID]
		if !ok {
			return nil, fmt.Errorf("class %s excludes %s, which is not an earlier class", spec.ID, classID)
		}
		for role, cases := range byRole {
			if excluded[role] == nil {
				excluded[role] = map[string]bool{}
			}
			for caseID := range cases {
				excluded[role][caseID] = true
			}
		}
	}

	out := map[string][]string{}
	for _, role := range roles {
		for _, difference := range sweep.DifferencesByRoleDimension(role, spec.Selector.Dimension) {
			if len(spec.Selector.Verdicts) > 0 && !containsVerdict(spec.Selector.Verdicts, difference.Verdict) {
				continue
			}
			if spec.Selector.PortValue != "" && canonical(difference.PortValue) != spec.Selector.PortValue {
				continue
			}
			if spec.Selector.JavaValue != "" && canonical(difference.JavaValue) != spec.Selector.JavaValue {
				continue
			}
			if excluded[role][difference.CaseID] {
				continue
			}
			out[role] = append(out[role], difference.CaseID)
		}
		sort.Strings(out[role])
	}
	return out, nil
}

func containsVerdict(list []Verdict, want Verdict) bool {
	for _, verdict := range list {
		if verdict == want {
			return true
		}
	}
	return false
}
