package formalplan

// Lane B (US-006): bounded explicit-state walker over the connection model's
// transition relation (assurance/formal/connection-model.tla), added for the
// round-1 review BLOCKING-1 remediation. The reviewer found, by hand, a
// reachable violation of TruncatedTailStaging that the static validator
// cannot see (it checks structure, not reachability). This walker closes that
// class: it enumerates EVERY reachable state under the shipped cfg bounds and
// checks every configured INVARIANT on every state, plus the TerminalAbsorbing
// action property on every transition, and it executes the seeded mutations to
// confirm each one actually produces a counterexample (non-vacuity).
//
// HONESTY BOX -- what this walker is and is not:
//   - It is a HAND-TRANSLATED Go replica of the TLA+ transition relation. It
//     does not parse connection-model.tla, so a translation divergence between
//     the two artifacts is a residual risk; any edit to the model's actions or
//     invariants MUST be mirrored here (the reviewer-trace and mutation tests
//     below are designed to fail loudly on the known-dangerous divergences).
//   - It is a test of the model artifact, not TLC and not proof: no SANY
//     grammar check, no liveness. The ClosingLeadsToClosed fairness property
//     is NOT checked here and remains MODEL_CHECK_PENDING_TOOL.
//   - It is not the port and not a proof-only duplicate implementation of the
//     shipped Java lifecycle: it exists solely to check the model artifact.

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"
)

// mwBounds are the model constants, read from the shipped cfg so the walker
// cannot silently drift from the TLC configuration.
type mwBounds struct {
	QueueCapacity int
	MaxSends      int
	MaxInbound    int
}

func mwLoadBounds(t *testing.T) mwBounds {
	t.Helper()
	text, failure := mpReadText(mpTestCfgPath)
	if failure != nil {
		t.Fatalf("read shipped cfg: %+v", *failure)
	}
	cfg, findings := mpParseCfg(text)
	if len(findings) != 0 {
		t.Fatalf("shipped cfg failed to parse: %+v", findings)
	}
	read := func(name string) int {
		value, ok := cfg.Constants[name]
		if !ok {
			t.Fatalf("shipped cfg does not assign %s", name)
		}
		var bound int
		if _, err := fmt.Sscanf(value, "%d", &bound); err != nil || bound < 1 {
			t.Fatalf("shipped cfg %s = %q is not a positive integer", name, value)
		}
		return bound
	}
	return mwBounds{
		QueueCapacity: read("QueueCapacity"),
		MaxSends:      read("MaxSends"),
		MaxInbound:    read("MaxInbound"),
	}
}

// mwState mirrors the model's variables. outQ encodes the queue head-first:
// 'd' = "data", 'c' = "close". The struct is comparable so it can key the
// visited set directly.
type mwState struct {
	state        string
	outQ         string
	sendCount    int
	inboundCount int
	terminal     int
	closeOrigin  string
	closeCode    int
	lastClass    string
	lastKind     string
	lastCode     int
	pending      bool
	dropped      int
	rejected     int
}

// mwMutations are the seeded defects from assurance/concurrency/plan.json,
// applied one at a time; the zero value is the unmutated model.
type mwMutations struct {
	initCloseCodeFive     bool // defect.model.type-domain-escape
	eofEnabledWhenClosed  bool // defect.model.double-terminal-delivery
	drainNoTerminal       bool // defect.model.closed-without-terminal-event
	localCloseNoDetail    bool // defect.model.closing-without-close-detail
	processRejectCode1000 bool // defect.model.error-close-with-normal-code
	emptyAcceptCode1002   bool // defect.model.empty-close-misnormalized
	sendUnbounded         bool // defect.model.unbounded-enqueue
	truncSingleStage      bool // defect.model.truncated-tail-single-stage
	truncSurvivesClose    bool // defect.model.truncated-tail-survives-close
	reopenAfterTerminal   bool // defect.model.reopen-after-terminal
}

func mwInit(m mwMutations) mwState {
	s := mwState{
		state:       "Connecting",
		closeOrigin: "none",
		lastClass:   "none",
		lastKind:    "none",
	}
	if m.initCloseCodeFive {
		s.closeCode = 5
	}
	return s
}

func mwAcceptCode(m mwMutations, class string) int {
	switch class {
	case "empty":
		if m.emptyAcceptCode1002 {
			return 1002
		}
		return 1000
	case "one_byte":
		return 1002
	case "valid_code_reason":
		return 1000
	}
	panic("unknown accept class " + class)
}

func mwInvalidDataCode(class string) int {
	switch class {
	case "code_1007_empty_reason":
		return 1007
	case "reserved_or_invalid_code":
		return 1002
	}
	panic("unknown invalid-data class " + class)
}

// mwStep is one enabled transition: the model action name (with the close
// class where the action is parameterized) and the successor state.
type mwStep struct {
	action string
	next   mwState
}

// mwSuccessors mirrors the model's Next relation. The terminal Done
// self-stutter is omitted: it changes nothing and cannot affect any state
// invariant or the TerminalAbsorbing check.
func mwSuccessors(b mwBounds, m mwMutations, s mwState) []mwStep {
	var steps []mwStep
	add := func(action string, next mwState) {
		steps = append(steps, mwStep{action: action, next: next})
	}

	// OpenHandshake
	if s.state == "Connecting" {
		n := s
		n.state = "Open"
		add("OpenHandshake", n)
	}

	// SendData (mutation: drop the queue-capacity guard)
	if s.state == "Open" && s.sendCount < b.MaxSends &&
		(m.sendUnbounded || len(s.outQ) < b.QueueCapacity) {
		n := s
		n.outQ += "d"
		n.sendCount++
		add("SendData", n)
	}

	// RecvDataFrame
	if s.state == "Open" && s.inboundCount < b.MaxInbound {
		n := s
		n.inboundCount++
		add("RecvDataFrame", n)
	}

	// RecvTextTruncatedTail (mutation: leave inboundCount unchanged)
	if s.state == "Open" && !s.pending && s.inboundCount < b.MaxInbound {
		n := s
		if !m.truncSingleStage {
			n.inboundCount++
		}
		n.pending = true
		add("RecvTextTruncatedTail", n)
	}

	// ProcessRejectTruncatedTail (mutation: emit 1000 instead of 1007)
	if s.state == "Open" && s.pending && len(s.outQ) < b.QueueCapacity {
		n := s
		n.pending = false
		n.state = "Closing"
		n.closeOrigin = "error"
		if m.processRejectCode1000 {
			n.closeCode = 1000
		} else {
			n.closeCode = 1007
		}
		n.outQ += "c"
		add("ProcessRejectTruncatedTail", n)
	}

	// RecvCloseAccept(c): discards a staged truncated tail (Java: close()
	// no-ops once CLOSING, WebSocketImpl.java:463-464).
	if s.state == "Open" && s.inboundCount < b.MaxInbound && len(s.outQ) < b.QueueCapacity {
		for _, class := range []string{"empty", "one_byte", "valid_code_reason"} {
			n := s
			n.inboundCount++
			n.lastClass = class
			n.lastKind = "accept"
			n.lastCode = mwAcceptCode(m, class)
			n.closeOrigin = "remote"
			n.closeCode = mwAcceptCode(m, class)
			n.outQ += "c"
			n.state = "Closing"
			n.pending = false
			add("RecvCloseAccept("+class+")", n)
		}
		for _, class := range []string{"code_1007_empty_reason", "reserved_or_invalid_code"} {
			n := s
			n.inboundCount++
			n.lastClass = class
			n.lastKind = "invalid_data"
			n.lastCode = mwInvalidDataCode(class)
			n.closeOrigin = "error"
			n.closeCode = mwInvalidDataCode(class)
			n.outQ += "c"
			n.state = "Closing"
			n.pending = false
			add("RecvCloseInvalidData("+class+")", n)
		}
	}

	// RecvCloseUtf8ReasonRuntimeRejection: stays OPEN, staged tail untouched.
	if s.state == "Open" && s.inboundCount < b.MaxInbound {
		n := s
		n.inboundCount++
		n.lastClass = "invalid_utf8_reason"
		n.lastKind = "runtime_rejection"
		n.lastCode = 0
		add("RecvCloseUtf8ReasonRuntimeRejection", n)
	}

	// LocalCloseValid (mutations: keep closeDetail; keep the staged tail --
	// the round-1 BLOCKING-1 defect class).
	if s.state == "Open" && len(s.outQ) < b.QueueCapacity {
		n := s
		if !m.localCloseNoDetail {
			n.closeOrigin = "local"
			n.closeCode = 1000
		}
		n.outQ += "c"
		n.state = "Closing"
		if !m.truncSurvivesClose {
			n.pending = false
		}
		add("LocalCloseValid", n)
	}

	// LocalCloseInvalidCode
	if s.state == "Open" && s.rejected < 1 {
		n := s
		n.rejected++
		n.closeOrigin = "error"
		n.closeCode = 1006
		n.state = "Closing"
		n.pending = false
		add("LocalCloseInvalidCode", n)
	}

	// FlushWrite
	if (s.state == "Open" || s.state == "Closing") && len(s.outQ) > 0 {
		n := s
		n.outQ = s.outQ[1:]
		add("FlushWrite", n)
	}

	// RecvCloseWhileClosing
	if s.state == "Closing" && s.inboundCount < b.MaxInbound {
		n := s
		n.inboundCount++
		n.lastClass = "empty"
		n.lastKind = "accept"
		n.lastCode = 1000
		n.closeOrigin = "remote"
		n.closeCode = 1000
		n.state = "Closed"
		n.terminal++
		n.dropped = len(s.outQ)
		n.outQ = ""
		n.pending = false
		add("RecvCloseWhileClosing", n)
	}

	// CloseOnDrain (mutation: forget the terminal delivery)
	if s.state == "Closing" && len(s.outQ) == 0 {
		n := s
		n.state = "Closed"
		if !m.drainNoTerminal {
			n.terminal++
		}
		n.pending = false
		add("CloseOnDrain", n)
	}

	// TransportEOF (mutation: also enabled once Closed)
	if s.state == "Connecting" || s.state == "Open" || s.state == "Closing" ||
		(m.eofEnabledWhenClosed && s.state == "Closed") {
		n := s
		n.closeOrigin = "transport"
		switch s.state {
		case "Closing":
			n.closeCode = s.closeCode
		case "Connecting":
			n.closeCode = -1
		default:
			n.closeCode = 1006
		}
		n.state = "Closed"
		n.terminal++
		n.dropped = len(s.outQ)
		n.outQ = ""
		n.pending = false
		add("TransportEOF", n)
	}

	// Reopen exists only under the seeded TerminalAbsorbing mutation.
	if m.reopenAfterTerminal && s.state == "Closed" {
		n := s
		n.state = "Open"
		add("Reopen", n)
	}

	return steps
}

func mwIntIn(v, lo, hi int) bool { return v >= lo && v <= hi }

func mwIn(v string, set ...string) bool {
	for _, member := range set {
		if v == member {
			return true
		}
	}
	return false
}

var mwCloseCodes = map[int]bool{-1: true, 0: true, 1000: true, 1002: true, 1006: true, 1007: true}

// mwViolations returns the names of every checked state invariant the state
// violates, mirroring the cfg's INVARIANT list one for one.
func mwViolations(b mwBounds, s mwState) []string {
	var violated []string

	typeOK := mwIn(s.state, "Connecting", "Open", "Closing", "Closed") &&
		mwIntIn(s.sendCount, 0, b.MaxSends) &&
		mwIntIn(s.inboundCount, 0, b.MaxInbound) &&
		mwIntIn(s.terminal, 0, 2) &&
		mwIn(s.closeOrigin, "none", "local", "remote", "transport", "error") &&
		mwCloseCodes[s.closeCode] &&
		mwIn(s.lastClass, "none", "empty", "one_byte", "valid_code_reason",
			"code_1007_empty_reason", "reserved_or_invalid_code", "invalid_utf8_reason") &&
		mwIn(s.lastKind, "none", "accept", "invalid_data", "runtime_rejection") &&
		mwCloseCodes[s.lastCode] &&
		mwIntIn(s.dropped, 0, b.QueueCapacity) &&
		mwIntIn(s.rejected, 0, 1)
	for _, kind := range s.outQ {
		if kind != 'd' && kind != 'c' {
			typeOK = false
		}
	}
	if !typeOK {
		violated = append(violated, "TypeInvariant")
	}

	if s.terminal > 1 {
		violated = append(violated, "TerminalDeliveredAtMostOnce")
	}
	if s.state == "Closed" && s.terminal != 1 {
		violated = append(violated, "ClosedImpliesTerminalDeliveredOnce")
	}
	if (s.state == "Closing" || s.state == "Closed") && s.closeOrigin == "none" {
		violated = append(violated, "CloseDetailPresentFromClosing")
	}
	if s.closeOrigin == "error" &&
		s.closeCode != 1002 && s.closeCode != 1006 && s.closeCode != 1007 {
		violated = append(violated, "ErrorCloseCodeDomain")
	}

	normalizationOK := true
	check := func(class, kind string, code int) {
		if s.lastClass == class && (s.lastKind != kind || s.lastCode != code) {
			normalizationOK = false
		}
	}
	check("empty", "accept", 1000)
	check("one_byte", "accept", 1002)
	check("valid_code_reason", "accept", 1000)
	check("code_1007_empty_reason", "invalid_data", 1007)
	check("reserved_or_invalid_code", "invalid_data", 1002)
	if s.lastClass == "invalid_utf8_reason" && s.lastKind != "runtime_rejection" {
		normalizationOK = false
	}
	if !normalizationOK {
		violated = append(violated, "InboundCloseNormalization")
	}

	if len(s.outQ) > b.QueueCapacity {
		violated = append(violated, "QueueNeverExceedsCapacity")
	}
	if s.pending && !(s.state == "Open" && s.inboundCount >= 1) {
		violated = append(violated, "TruncatedTailStaging")
	}

	return violated
}

// mwWalkResult is the outcome of an exhaustive bounded walk.
type mwWalkResult struct {
	reachable    int
	violations   map[string][]string // invariant (or TerminalAbsorbing) -> one witness trace
	actionsFired map[string]int
}

// mwWalk explores the full reachable state space (BFS). States that violate
// an invariant are recorded with a witness trace and, like TLC, not expanded
// further, which keeps mutated walks finite and traces minimal.
func mwWalk(b mwBounds, m mwMutations) mwWalkResult {
	type visit struct {
		state mwState
		trace []string
	}
	result := mwWalkResult{
		violations:   map[string][]string{},
		actionsFired: map[string]int{},
	}
	init := mwInit(m)
	visited := map[mwState]bool{init: true}
	queue := []visit{{state: init, trace: []string{"Init"}}}
	if names := mwViolations(b, init); len(names) != 0 {
		for _, name := range names {
			result.violations[name] = []string{"Init"}
		}
		queue = nil
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		result.reachable++
		for _, step := range mwSuccessors(b, m, current.state) {
			result.actionsFired[step.action]++
			trace := append(append([]string{}, current.trace...), step.action)
			if current.state.state == "Closed" && step.next.state != "Closed" {
				if _, seen := result.violations["TerminalAbsorbing"]; !seen {
					result.violations["TerminalAbsorbing"] = trace
				}
			}
			if visited[step.next] {
				continue
			}
			visited[step.next] = true
			if names := mwViolations(b, step.next); len(names) != 0 {
				for _, name := range names {
					if _, seen := result.violations[name]; !seen {
						result.violations[name] = trace
					}
				}
				continue // do not expand violating states
			}
			queue = append(queue, visit{state: step.next, trace: trace})
		}
	}
	return result
}

// TestModelWalkerUnmutatedModelHoldsAllInvariants is the mechanized version
// of the round-1 "hand-walk every action against every invariant" obligation:
// every configured state invariant holds on every reachable state under the
// shipped cfg bounds, and TerminalAbsorbing holds on every transition.
func TestModelWalkerUnmutatedModelHoldsAllInvariants(t *testing.T) {
	bounds := mwLoadBounds(t)
	result := mwWalk(bounds, mwMutations{})
	if len(result.violations) != 0 {
		for name, trace := range result.violations {
			t.Errorf("invariant %s violated; witness trace: %s", name, strings.Join(trace, " -> "))
		}
		t.Fatalf("unmutated model has reachable violations")
	}
	if result.reachable < 100 {
		t.Fatalf("suspiciously small reachable state space (%d states); walker guards may be wrong", result.reachable)
	}
	// Every modeled action must actually fire somewhere, or the walk (and the
	// invariant results) would be vacuous for the silent action.
	for _, action := range []string{
		"OpenHandshake", "SendData", "RecvDataFrame", "RecvTextTruncatedTail",
		"ProcessRejectTruncatedTail",
		"RecvCloseAccept(empty)", "RecvCloseAccept(one_byte)", "RecvCloseAccept(valid_code_reason)",
		"RecvCloseInvalidData(code_1007_empty_reason)", "RecvCloseInvalidData(reserved_or_invalid_code)",
		"RecvCloseUtf8ReasonRuntimeRejection", "LocalCloseValid", "LocalCloseInvalidCode",
		"FlushWrite", "RecvCloseWhileClosing", "CloseOnDrain", "TransportEOF",
	} {
		if result.actionsFired[action] == 0 {
			t.Errorf("action %s never fired during the exhaustive walk", action)
		}
	}
}

// TestModelWalkerReviewerTraceIsDischarged replays the exact round-1 BLOCKING-1
// counterexample trace (Init -> OpenHandshake -> RecvTextTruncatedTail ->
// LocalCloseValid) and the inbound-close variants of the same failure, and
// asserts the corrected model discards the staged rejection on each of them.
func TestModelWalkerReviewerTraceIsDischarged(t *testing.T) {
	bounds := mwLoadBounds(t)
	closers := []string{
		"LocalCloseValid",
		"LocalCloseInvalidCode",
		"RecvCloseAccept(empty)",
		"RecvCloseAccept(one_byte)",
		"RecvCloseAccept(valid_code_reason)",
		"RecvCloseInvalidData(code_1007_empty_reason)",
		"RecvCloseInvalidData(reserved_or_invalid_code)",
	}
	for _, closer := range closers {
		state := mwInit(mwMutations{})
		for _, action := range []string{"OpenHandshake", "RecvTextTruncatedTail", closer} {
			var next *mwState
			for _, step := range mwSuccessors(bounds, mwMutations{}, state) {
				if step.action == action {
					candidate := step.next
					next = &candidate
					break
				}
			}
			if next == nil {
				t.Fatalf("action %s not enabled on the reviewer trace", action)
			}
			state = *next
		}
		if state.state != "Closing" {
			t.Fatalf("%s: expected Closing after the reviewer trace, got %s", closer, state.state)
		}
		if state.pending {
			t.Fatalf("%s: staged truncated-tail rejection survived the close transition (round-1 BLOCKING-1 regression)", closer)
		}
		if names := mwViolations(bounds, state); len(names) != 0 {
			t.Fatalf("%s: reviewer trace still violates %v", closer, names)
		}
	}
}

// TestModelWalkerSeededMutationsProduceCounterexamples executes every seeded
// defect from assurance/concurrency/plan.json that a state-space walk can
// express and requires each to violate exactly its declared target property
// (non-vacuity). defect.model.starved-closing-resolution targets the
// ClosingLeadsToClosed liveness property, which a plain reachability walk
// cannot falsify; it remains MODEL_CHECK_PENDING_TOOL and is deliberately
// absent here.
func TestModelWalkerSeededMutationsProduceCounterexamples(t *testing.T) {
	bounds := mwLoadBounds(t)
	// Round-2 review finding: asserting only that the declared target appears
	// among the violations does not establish mutation specificity — a
	// mutation may (and two genuinely do) violate additional invariants. Each
	// case now declares its EXACT expected violation set and the walker
	// asserts set equality, so an undeclared extra violation (or a missing
	// declared one) fails the test.
	cases := []struct {
		defect   string
		mutate   mwMutations
		target   string
		expected []string
	}{
		{"defect.model.type-domain-escape", mwMutations{initCloseCodeFive: true}, "TypeInvariant",
			[]string{"TypeInvariant"}},
		{"defect.model.double-terminal-delivery", mwMutations{eofEnabledWhenClosed: true}, "TerminalDeliveredAtMostOnce",
			[]string{"ClosedImpliesTerminalDeliveredOnce", "TerminalDeliveredAtMostOnce"}},
		{"defect.model.closed-without-terminal-event", mwMutations{drainNoTerminal: true}, "ClosedImpliesTerminalDeliveredOnce",
			[]string{"ClosedImpliesTerminalDeliveredOnce"}},
		{"defect.model.closing-without-close-detail", mwMutations{localCloseNoDetail: true}, "CloseDetailPresentFromClosing",
			[]string{"CloseDetailPresentFromClosing"}},
		{"defect.model.error-close-with-normal-code", mwMutations{processRejectCode1000: true}, "ErrorCloseCodeDomain",
			[]string{"ErrorCloseCodeDomain"}},
		{"defect.model.empty-close-misnormalized", mwMutations{emptyAcceptCode1002: true}, "InboundCloseNormalization",
			[]string{"InboundCloseNormalization"}},
		{"defect.model.unbounded-enqueue", mwMutations{sendUnbounded: true}, "QueueNeverExceedsCapacity",
			[]string{"QueueNeverExceedsCapacity"}},
		{"defect.model.truncated-tail-single-stage", mwMutations{truncSingleStage: true}, "TruncatedTailStaging",
			[]string{"TruncatedTailStaging"}},
		{"defect.model.truncated-tail-survives-close", mwMutations{truncSurvivesClose: true}, "TruncatedTailStaging",
			[]string{"TruncatedTailStaging"}},
		{"defect.model.reopen-after-terminal", mwMutations{reopenAfterTerminal: true}, "TerminalAbsorbing",
			[]string{"ClosedImpliesTerminalDeliveredOnce", "TerminalAbsorbing", "TerminalDeliveredAtMostOnce"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.defect, func(t *testing.T) {
			result := mwWalk(bounds, testCase.mutate)
			trace, found := result.violations[testCase.target]
			if !found {
				t.Fatalf("mutation did not violate its target %s (violations: %v)", testCase.target, result.violations)
			}
			actual := make([]string, 0, len(result.violations))
			for name := range result.violations {
				actual = append(actual, name)
			}
			sort.Strings(actual)
			expected := append([]string(nil), testCase.expected...)
			sort.Strings(expected)
			if !slices.Equal(actual, expected) {
				t.Fatalf("mutation violation set %v does not equal the declared set %v", actual, expected)
			}
			t.Logf("counterexample: %s", strings.Join(trace, " -> "))
		})
	}
}

// TestModelWalkerSurvivesCloseTraceMatchesReviewer pins the witness for the
// truncated-tail-survives-close defect to the reviewer's exact trace shape:
// the violation must be reachable through LocalCloseValid with the staged
// rejection still live.
func TestModelWalkerSurvivesCloseTraceMatchesReviewer(t *testing.T) {
	bounds := mwLoadBounds(t)
	result := mwWalk(bounds, mwMutations{truncSurvivesClose: true})
	trace, found := result.violations["TruncatedTailStaging"]
	if !found {
		t.Fatalf("expected a TruncatedTailStaging violation")
	}
	// Round-2 review finding: containment of two action names is not the
	// reviewer's trace. Pin the exact ordered witness.
	want := []string{"Init", "OpenHandshake", "RecvTextTruncatedTail", "LocalCloseValid"}
	if !slices.Equal(trace, want) {
		t.Fatalf("witness trace %v is not the reviewer's exact trace %v", trace, want)
	}
}
