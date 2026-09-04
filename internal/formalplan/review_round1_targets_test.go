package formalplan

// Lane A (US-006) re-review round 1 regression tests. Review session 01a04047
// BLOCKed on two formal-language-exceeds-shipped-behavior findings:
//
//   BLOCKING-1: the close.terminal-absorbing target claimed exactly-once
//   terminal delivery, but the quarantined Java fires onWebsocketClose
//   (WebSocketImpl.java:557) BEFORE setting readyState = CLOSED (:566) inside
//   a reentrant synchronized monitor (:530), so a listener re-entering
//   closeConnection from the callback passes the :531-533 CLOSED guard and
//   receives a second terminal callback — shipped delivery is at-least-once.
//
//   BLOCKING-2: the framing.length-bounds target claimed the shipped decoder
//   uses checked arithmetic, but realpacketsize += payloadlength
//   (Draft_6455.java:554) is plain int arithmetic that can overflow BEFORE
//   translateSingleFrameCheckPacketSize compares it (:555, :670-676).
//
// These tests pin (a) the shipped Java reality inside the digest-pinned
// quarantined tree and (b) the corrected claim language plus the
// PENDING_BEHAVIOR_DELTA_LEDGER_ENTRY strengthening notes, so neither
// overclaim can silently return.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/portplan"
)

func targetsRound1JavaLines(t *testing.T, root, relFile string) []string {
	t.Helper()
	treePath, err := portplan.EnsureQuarantinedSource(root)
	if err != nil {
		t.Fatalf("quarantined tree unavailable: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(treePath, filepath.FromSlash(relFile)))
	if err != nil {
		t.Fatalf("read quarantined %s: %v", relFile, err)
	}
	return strings.Split(string(content), "\n")
}

func targetsRound1JavaLine(t *testing.T, lines []string, number int, mustContain string) {
	t.Helper()
	if number < 1 || number > len(lines) {
		t.Fatalf("line %d out of range (%d lines)", number, len(lines))
	}
	if !strings.Contains(lines[number-1], mustContain) {
		t.Fatalf("quarantined line %d = %q, want it to contain %q — the pinned Java reality this claim cites has moved; re-verify the claim before touching this test",
			number, strings.TrimSpace(lines[number-1]), mustContain)
	}
}

func targetsRound1FindTarget(t *testing.T, document *ProofTargetsDocument, claim string) *ProofTarget {
	t.Helper()
	for index := range document.Targets {
		if document.Targets[index].FormalClaimID == claim {
			return &document.Targets[index]
		}
	}
	t.Fatalf("target for claim %s missing", claim)
	return nil
}

func targetsRound1FindNote(t *testing.T, target *ProofTarget, noteID string) *ProofTargetStrengtheningNote {
	t.Helper()
	for index := range target.BehaviorFidelity.StrengtheningNotes {
		if target.BehaviorFidelity.StrengtheningNotes[index].NoteID == noteID {
			return &target.BehaviorFidelity.StrengtheningNotes[index]
		}
	}
	t.Fatalf("target %s lacks strengthening note %s", target.TargetID, noteID)
	return nil
}

func targetsRound1RequirePendingNote(t *testing.T, note *ProofTargetStrengtheningNote, story string) {
	t.Helper()
	if note.State != targetsNotePending {
		t.Errorf("note %s state = %q, want %s (a strengthening is never the current formal claim)",
			note.NoteID, note.State, targetsNotePending)
	}
	if note.LedgerRecordID != nil {
		t.Errorf("note %s cites ledger record %q while pending; the ledger carries no such record",
			note.NoteID, *note.LedgerRecordID)
	}
	if note.ImplementingStory != story {
		t.Errorf("note %s implementing story = %q, want %q", note.NoteID, note.ImplementingStory, story)
	}
}

// TestTargetsRound1CloseClaimMatchesShippedReentrancy pins BLOCKING-1: the
// shipped callback-before-CLOSED ordering under a reentrant monitor, and the
// corrected at-least-once claim with the exactly-once strengthening recorded
// only as a pending ledger obligation.
func TestTargetsRound1CloseClaimMatchesShippedReentrancy(t *testing.T) {
	root := targetsRepoRoot(t)

	lines := targetsRound1JavaLines(t, root, "src/main/java/org/java_websocket/WebSocketImpl.java")
	targetsRound1JavaLine(t, lines, 530, "synchronized void closeConnection")
	targetsRound1JavaLine(t, lines, 531, "readyState == ReadyState.CLOSED")
	targetsRound1JavaLine(t, lines, 557, "onWebsocketClose(")
	targetsRound1JavaLine(t, lines, 566, "readyState = ReadyState.CLOSED")

	document, err := LoadProofTargets(root)
	if err != nil {
		t.Fatalf("load proof targets: %v", err)
	}
	target := targetsRound1FindTarget(t, document, "formal.close.terminal-absorbing")

	if strings.Contains(target.Statement, "delivers onWebsocketClose exactly once") {
		t.Errorf("close statement still overclaims exactly-once delivery: %q", target.Statement)
	}
	if !strings.Contains(target.Statement, "at-least-once") {
		t.Errorf("close statement must state the shipped at-least-once terminal delivery: %q", target.Statement)
	}
	if !strings.Contains(target.Statement, "reentrant") {
		t.Errorf("close statement must cite the reentrancy path that makes duplicate delivery representable: %q", target.Statement)
	}
	for _, anchor := range target.JavaAuthority {
		if anchor.AnchorID != "anchor.close.close-connection" {
			continue
		}
		if strings.Contains(anchor.Behavior, "exactly-once onWebsocketClose") {
			t.Errorf("close-connection anchor still overclaims exactly-once: %q", anchor.Behavior)
		}
		if !strings.Contains(anchor.Behavior, "at-least-once") {
			t.Errorf("close-connection anchor must describe at-least-once delivery: %q", anchor.Behavior)
		}
	}

	note := targetsRound1FindNote(t, target, "note.close.exactly-once-terminal-delivery")
	targetsRound1RequirePendingNote(t, note, "US-009")
}

// TestTargetsRound1ArithmeticClaimMatchesShippedOverflow pins BLOCKING-2: the
// shipped unchecked int accumulation before the packet-size comparison, and
// the corrected claim with the checked-arithmetic strengthening recorded only
// as a pending ledger obligation.
func TestTargetsRound1ArithmeticClaimMatchesShippedOverflow(t *testing.T) {
	root := targetsRepoRoot(t)

	lines := targetsRound1JavaLines(t, root, "src/main/java/org/java_websocket/drafts/Draft_6455.java")
	targetsRound1JavaLine(t, lines, 534, "int realpacketsize = 2")
	targetsRound1JavaLine(t, lines, 554, "realpacketsize += payloadlength")
	targetsRound1JavaLine(t, lines, 555, "translateSingleFrameCheckPacketSize")

	document, err := LoadProofTargets(root)
	if err != nil {
		t.Fatalf("load proof targets: %v", err)
	}
	target := targetsRound1FindTarget(t, document, "formal.framing.length-bounds")

	if strings.Contains(target.Statement, "with checked arithmetic") {
		t.Errorf("length-bounds statement still claims the shipped decode is checked arithmetic: %q", target.Statement)
	}
	if !strings.Contains(target.Statement, "NOT checked arithmetic") {
		t.Errorf("length-bounds statement must state the shipped accumulation is not checked arithmetic: %q", target.Statement)
	}
	if !strings.Contains(target.Statement, "overflow") {
		t.Errorf("length-bounds statement must describe the overflow-before-comparison hazard: %q", target.Statement)
	}

	note := targetsRound1FindNote(t, target, "note.framing.checked-packet-size-arithmetic")
	targetsRound1RequirePendingNote(t, note, "US-012")
}

// TestTargetsRound1SweepClaimsMatchShippedSemantics pins the sweep over the
// other targets for the same overclaim class ('every', 'cannot grow without
// bound', 'incrementally', 'exactly-once') against the shipped Java:
//   - allocation-limit: the reassembly allocation (Draft_6455.java:1171) is
//     checkBufferLimit-guarded, not checkAlloc-guarded, so "every frame-path
//     allocation is guarded by checkAlloc" was false;
//   - fragmentation: intermediate CONTINUOUS non-fin fragments append (:946)
//     with no checkBufferLimit call, so growth is bounded only at the
//     start/fin checkpoints, not per-append;
//   - utf8: isValidUTF8 runs only for the initial TEXT-opcode fragment
//     (:940-943), never for CONTINUOUS fragments;
//   - concurrency: the close monitor gives exactly-once initiation but not
//     unqualified exactly-once terminal delivery (see BLOCKING-1).
func TestTargetsRound1SweepClaimsMatchShippedSemantics(t *testing.T) {
	root := targetsRepoRoot(t)

	lines := targetsRound1JavaLines(t, root, "src/main/java/org/java_websocket/drafts/Draft_6455.java")
	targetsRound1JavaLine(t, lines, 946, "addToBufferList")
	targetsRound1JavaLine(t, lines, 940, "isValidUTF8")
	targetsRound1JavaLine(t, lines, 1170, "checkBufferLimit")
	targetsRound1JavaLine(t, lines, 1171, "ByteBuffer.allocate((int) totalSize)")
	if strings.Contains(lines[946], "checkBufferLimit") {
		t.Fatalf("line 947 now calls checkBufferLimit; the shipped per-append gap this sweep documents has moved")
	}

	document, err := LoadProofTargets(root)
	if err != nil {
		t.Fatalf("load proof targets: %v", err)
	}

	allocation := targetsRound1FindTarget(t, document, "formal.framing.allocation-limit")
	if strings.Contains(allocation.Statement, "Every frame-path allocation") {
		t.Errorf("allocation statement still claims every frame-path allocation is checkAlloc-guarded: %q", allocation.Statement)
	}
	if !strings.Contains(allocation.Statement, "checkBufferLimit") || !strings.Contains(allocation.Statement, "1171") {
		t.Errorf("allocation statement must cite the checkBufferLimit-guarded reassembly allocation at 1171: %q", allocation.Statement)
	}
	foundReassemblyAnchor := false
	for _, anchor := range allocation.JavaAuthority {
		if anchor.AnchorID == "anchor.allocation-limit.reassembly-alloc" {
			foundReassemblyAnchor = true
		}
	}
	if !foundReassemblyAnchor {
		t.Errorf("allocation target must anchor getPayloadFromByteBufferList so the corrected claim stays citable")
	}

	fragmentation := targetsRound1FindTarget(t, document, "formal.fragmentation.no-unbounded-growth")
	if strings.Contains(fragmentation.Statement, "cannot grow without bound") {
		t.Errorf("fragmentation statement still claims a bound the shipped code does not enforce per-append: %q", fragmentation.Statement)
	}
	// Round-2 finding: the TITLE must not overclaim what the statement
	// disavows — "Bounded" without qualification contradicts the recorded
	// unbounded intermediate growth.
	if strings.HasPrefix(fragmentation.Title, "Bounded ") {
		t.Errorf("fragmentation title still overclaims boundedness the shipped code does not enforce: %q", fragmentation.Title)
	}
	if !strings.Contains(fragmentation.Title, "unbounded") {
		t.Errorf("fragmentation title must carry the shipped unbounded-intermediate-growth caveat: %q", fragmentation.Title)
	}
	if !strings.Contains(fragmentation.Statement, "946") || !strings.Contains(fragmentation.Statement, "checkBufferLimit") {
		t.Errorf("fragmentation statement must cite the unchecked intermediate append at 946: %q", fragmentation.Statement)
	}
	fragNote := targetsRound1FindNote(t, fragmentation, "note.fragmentation.per-append-buffer-cap")
	targetsRound1RequirePendingNote(t, fragNote, "US-012")

	utf8 := targetsRound1FindTarget(t, document, "formal.messages.utf8-validation-total")
	if strings.Contains(utf8.Statement, "fragmented text is additionally checked incrementally") {
		t.Errorf("utf8 statement still implies per-fragment incremental validation: %q", utf8.Statement)
	}
	if !strings.Contains(utf8.Statement, "initial TEXT-opcode fragment") || !strings.Contains(utf8.Statement, "CONTINUOUS") {
		t.Errorf("utf8 statement must scope isValidUTF8 to the initial TEXT-opcode fragment: %q", utf8.Statement)
	}

	concurrency := targetsRound1FindTarget(t, document, "formal.concurrency.no-data-race")
	for _, anchor := range concurrency.JavaAuthority {
		if anchor.AnchorID != "anchor.concurrency.close-monitor" {
			continue
		}
		if strings.Contains(anchor.Behavior, "exactly-once close initiation and terminal delivery") {
			t.Errorf("close-monitor anchor still claims unqualified exactly-once terminal delivery: %q", anchor.Behavior)
		}
		if !strings.Contains(anchor.Behavior, "reentrant") {
			t.Errorf("close-monitor anchor must cite the reentrancy caveat: %q", anchor.Behavior)
		}
	}
}

// TestTargetsRound1StrengtheningNotePairedStatesBlock drives the validator
// over seeded-bad strengthening notes: a pending note citing a ledger record,
// a ledgered note citing nothing, and a ledgered note citing a record the
// (empty) behavior-delta ledger does not carry all block with typed findings.
func TestTargetsRound1StrengtheningNotePairedStatesBlock(t *testing.T) {
	root := targetsRepoRoot(t)

	inject := func(note map[string]interface{}) func(document map[string]interface{}) {
		return func(document map[string]interface{}) {
			target := targetsFindByClaim(document, "formal.close.terminal-absorbing")
			fidelity := target["behavior_fidelity"].(map[string]interface{})
			fidelity["strengthening_notes"] = []interface{}{note}
		}
	}

	cases := []struct {
		name   string
		code   string
		mutate func(document map[string]interface{})
	}{
		{
			name: "pending-note-citing-ledger-record-blocks",
			code: TargetsFindingStrengtheningNoteStateInvalid,
			mutate: inject(map[string]interface{}{
				"note_id":            "note.close.exactly-once-terminal-delivery",
				"state":              "PENDING_BEHAVIOR_DELTA_LEDGER_ENTRY",
				"ledger_record_id":   "delta.close.exactly-once-terminal-delivery",
				"implementing_story": "US-009",
				"statement":          "pending note must not cite a record",
			}),
		},
		{
			name: "ledgered-note-citing-nothing-blocks",
			code: TargetsFindingStrengtheningNoteStateInvalid,
			mutate: inject(map[string]interface{}{
				"note_id":            "note.close.exactly-once-terminal-delivery",
				"state":              "LEDGERED",
				"ledger_record_id":   nil,
				"implementing_story": "US-009",
				"statement":          "ledgered note must cite a record",
			}),
		},
		{
			name: "ledgered-note-citing-absent-record-blocks",
			code: TargetsFindingStrengtheningNoteUnledgered,
			mutate: inject(map[string]interface{}{
				"note_id":            "note.close.exactly-once-terminal-delivery",
				"state":              "LEDGERED",
				"ledger_record_id":   "delta.close.exactly-once-terminal-delivery",
				"implementing_story": "US-009",
				"statement":          "the ledger carries no records at freeze",
			}),
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			path := targetsMutate(t, root, testCase.mutate)
			report := VerifyProofTargetsAt(root, path)
			targetsRequireCode(t, report, testCase.code)
		})
	}
}
