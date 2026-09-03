package rfcneutral

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
)

// synth builds a scenario from raw octet chunks. It never carries an
// expectation, because Scenario cannot hold one.
func synth(id, role string, chunks ...[]byte) Scenario {
	s := Scenario{ScenarioID: id, Role: role, InitialState: "open"}
	for _, c := range chunks {
		s.Steps = append(s.Steps, Step{Kind: "bytes", Data: base64.StdEncoding.EncodeToString(c)})
	}
	return s
}

// frameBytes assembles one frame. mask is applied when key is non-nil.
func frameBytes(fin bool, rsv byte, opcode byte, payload []byte, key []byte) []byte {
	b0 := opcode & 0x0F
	if fin {
		b0 |= 0x80
	}
	b0 |= rsv << 4
	out := []byte{b0}

	n := uint64(len(payload))
	maskBit := byte(0)
	if key != nil {
		maskBit = 0x80
	}
	switch {
	case n < 126:
		out = append(out, maskBit|byte(n))
	case n < 65536:
		out = append(out, maskBit|126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(n))
		out = append(out, ext[:]...)
	default:
		out = append(out, maskBit|127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], n)
		out = append(out, ext[:]...)
	}
	if key != nil {
		out = append(out, key...)
		masked := append([]byte(nil), payload...)
		for i := range masked {
			masked[i] ^= key[i%4]
		}
		return append(out, masked...)
	}
	return append(out, payload...)
}

func decideOne(t *testing.T, s Scenario) Decision {
	t.Helper()
	ds, err := DeriveScenarios([]Scenario{s})
	if err != nil {
		t.Fatalf("%s: %v", s.ScenarioID, err)
	}
	if len(ds) != 1 {
		t.Fatalf("%s: got %d decisions", s.ScenarioID, len(ds))
	}
	return ds[0]
}

func wantRule(t *testing.T, d Decision, ruleID, verdict string) {
	t.Helper()
	if d.RuleID != ruleID {
		t.Fatalf("%s: rule %q, want %q (detail %q)", d.ScenarioID, d.RuleID, ruleID, d.Detail)
	}
	if verdict == "" {
		if !d.Abstains {
			t.Fatalf("%s: verdict %q, want an abstention", d.ScenarioID, d.Verdict)
		}
		return
	}
	if d.Abstains || d.Verdict != verdict {
		t.Fatalf("%s: verdict %q (abstains=%v), want %q", d.ScenarioID, d.Verdict, d.Abstains, verdict)
	}
}

var key = []byte{0x11, 0x22, 0x33, 0x44}

// TestEveryDecidingRuleFires is the coverage floor. A rule in the table that no
// input can reach is a rule that exists in name only, so each one is driven
// here from octets built for it.
func TestEveryDecidingRuleFires(t *testing.T) {
	cases := []struct {
		name   string
		s      Scenario
		rule   string
		result string
	}{
		{"unmasked to server", synth("t-unmasked", "server", frameBytes(true, 0, opText, []byte("hi"), nil)),
			RuleUnmaskedToServer, VerdictClosed},
		{"masked to client", synth("t-masked", "client", frameBytes(true, 0, opText, []byte("hi"), key)),
			RuleMaskedToClient, VerdictClosed},
		{"rsv set", synth("t-rsv", "client", frameBytes(true, 0x4, opText, []byte("hi"), nil)),
			RuleReservedBit, VerdictClosed},
		{"reserved opcode", synth("t-op", "client", frameBytes(true, 0, 0x3, nil, nil)),
			RuleReservedOpcode, VerdictClosed},
		{"non-minimal 16-bit length", synth("t-len16", "client",
			[]byte{0x81, 126, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}),
			RuleNonMinimalLength, VerdictClosed},
		{"non-minimal 64-bit length", synth("t-len64", "client",
			append([]byte{0x81, 127, 0, 0, 0, 0, 0, 0, 0x00, 0x05}, []byte("hello")...)),
			RuleNonMinimalLength, VerdictClosed},
		{"64-bit high bit", synth("t-len64hi", "client",
			[]byte{0x81, 127, 0x80, 0, 0, 0, 0, 0, 0, 0x05}),
			RuleLength64HighBit, VerdictClosed},
		{"oversize control", synth("t-ctl", "client", frameBytes(true, 0, opPing, make([]byte, 126), nil)),
			RuleControlOversize, VerdictClosed},
		{"fragmented control", synth("t-ctlfrag", "client", frameBytes(false, 0, opPing, []byte("x"), nil)),
			RuleControlFragmented, VerdictClosed},
		{"orphan continuation", synth("t-cont", "client", frameBytes(true, 0, opContinuation, []byte("x"), nil)),
			RuleOrphanContinuation, VerdictClosed},
		{"interleaved data", synth("t-interleave", "client",
			frameBytes(false, 0, opText, []byte("a"), nil),
			frameBytes(true, 0, opBinary, []byte("b"), nil)),
			RuleInterleavedData, VerdictClosed},
		{"one-octet close body", synth("t-close1", "client", frameBytes(true, 0, opClose, []byte{0x03}, nil)),
			RuleCloseBodyLength1, VerdictClosed},
		{"undefined close code", synth("t-close999", "client",
			frameBytes(true, 0, opClose, []byte{0x03, 0xE7}, nil)),
			RuleCloseCodeInvalid, VerdictClosed},
		{"close reason not utf8", synth("t-closereason", "client",
			frameBytes(true, 0, opClose, []byte{0x03, 0xE8, 0xC3, 0x28}, nil)),
			RuleCloseReasonNotUTF8, VerdictClosed},
		{"text not utf8", synth("t-text", "client",
			frameBytes(true, 0, opText, []byte{0xC3, 0x28}, nil)),
			RuleTextNotUTF8, VerdictClosed},
		{"clean stream", synth("t-ok", "client", frameBytes(true, 0, opText, []byte("hello"), nil)),
			RuleNoViolation, VerdictOpen},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantRule(t, decideOne(t, tc.s), tc.rule, tc.result)
		})
		seen[tc.rule] = true
	}
	for _, r := range Rules() {
		if r.Effect == "" || seen[r.ID] {
			continue
		}
		t.Fatalf("deciding rule %q is in the table and no case here reaches it", r.ID)
	}
}

// TestEveryAbstainingRuleFires does the same for the abstentions. An
// abstention that cannot be reached is a rule that never declines anything.
func TestEveryAbstainingRuleFires(t *testing.T) {
	closedInit := synth("t-init", "client")
	closedInit.InitialState = "closed"

	action := Scenario{ScenarioID: "t-action", Role: "client", InitialState: "open",
		Steps: []Step{{Kind: "action", Action: "send_text"}}}

	limit := synth("t-limit", "client", frameBytes(true, 0, opText, []byte("hello"), nil))
	limit.Limits.MaxInputBytes = 3

	frames := synth("t-frames", "client",
		append(frameBytes(true, 0, opText, []byte("a"), nil), frameBytes(true, 0, opText, []byte("b"), nil)...))
	frames.Limits.MaxFrames = 1

	buffered := synth("t-buffered", "client", frameBytes(true, 0, opText, make([]byte, 40), nil))
	buffered.Limits.MaxBufferedBytes = 8

	closing := synth("t-closing", "client", frameBytes(true, 0, opClose, []byte{0x03, 0xE8}, nil))

	truncated := synth("t-trunc", "client", []byte{0x81, 0x05, 'h', 'i'})

	cases := []struct {
		name string
		s    Scenario
		rule string
	}{
		{"non-open initial state", closedInit, AbstainNonOpenInitialState},
		{"local action", action, AbstainLocalAPIAction},
		{"input limit", limit, AbstainHarnessLimit},
		{"frame limit", frames, AbstainHarnessLimit},
		{"buffered limit", buffered, AbstainHarnessLimit},
		{"closing handshake", closing, AbstainClosingHandshake},
		{"truncated trailer", truncated, AbstainTruncatedTrailer},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantRule(t, decideOne(t, tc.s), tc.rule, "")
		})
		seen[tc.rule] = true
	}
	for _, r := range Rules() {
		if r.Effect != "" || seen[r.ID] {
			continue
		}
		t.Fatalf("abstaining rule %q is in the table and no case here reaches it", r.ID)
	}
}

// TestValidCloseCodeBoundaries pins the section 7.4 reading at its edges. These
// are the boundaries a misreading moves, so they are asserted one by one.
func TestValidCloseCodeBoundaries(t *testing.T) {
	valid := []uint16{1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 3000, 3999, 4000, 4999}
	invalid := []uint16{0, 999, 1004, 1005, 1006, 1012, 1015, 1016, 2999, 2000, 5000, 65535}
	for _, c := range valid {
		if !validCloseCode(c) {
			t.Errorf("close code %d rejected; section 7.4 defines it for the wire", c)
		}
	}
	for _, c := range invalid {
		if validCloseCode(c) {
			t.Errorf("close code %d accepted; section 7.4 does not define it for the wire", c)
		}
	}
}

// TestFragmentedMessageCompletesCleanly proves the fragmentation tracker is not
// a rubber stamp: a well-formed fragmented message, with a control frame
// injected mid-message as section 5.4 permits, must decide open.
func TestFragmentedMessageCompletesCleanly(t *testing.T) {
	s := synth("t-frag", "client",
		frameBytes(false, 0, opText, []byte("he"), nil),
		frameBytes(true, 0, opPing, []byte("p"), nil),
		frameBytes(true, 0, opContinuation, []byte("llo"), nil))
	wantRule(t, decideOne(t, s), RuleNoViolation, VerdictOpen)
}

// TestFragmentedTextIsCheckedAfterReassembly proves UTF-8 validity is decided
// on the whole message: neither fragment alone is valid UTF-8 here, and the
// concatenation is, so a per-fragment check would wrongly report closed.
func TestFragmentedTextIsCheckedAfterReassembly(t *testing.T) {
	whole := []byte("éé") // two 2-octet runes
	s := synth("t-fragutf8", "client",
		frameBytes(false, 0, opText, whole[:1], nil),
		frameBytes(true, 0, opContinuation, whole[1:], nil))
	wantRule(t, decideOne(t, s), RuleNoViolation, VerdictOpen)

	bad := synth("t-fragutf8bad", "client",
		frameBytes(false, 0, opText, []byte{0xC3}, nil),
		frameBytes(true, 0, opContinuation, []byte{0x28}, nil))
	wantRule(t, decideOne(t, bad), RuleTextNotUTF8, VerdictClosed)
}

// TestRuleTableIsWellFormed keeps the transcription honest: every rule carries
// clauses and a reading, and every effect is inside the verdict space.
func TestRuleTableIsWellFormed(t *testing.T) {
	if len(Rules()) == 0 {
		t.Fatal("the rule table is empty")
	}
	for _, r := range Rules() {
		if r.ID == "" {
			t.Fatal("a rule has no id")
		}
		if len(r.Clauses) == 0 {
			t.Fatalf("rule %q cites no clause; a reading with no clause cannot be checked against the text", r.ID)
		}
		if len(r.Quote) < 40 {
			t.Fatalf("rule %q records a %d-character reading; the sentence the rule rests on has to be legible", r.ID, len(r.Quote))
		}
		switch r.Effect {
		case "", VerdictOpen, VerdictClosed:
		default:
			t.Fatalf("rule %q has effect %q, which is outside the verdict space", r.ID, r.Effect)
		}
	}
}
