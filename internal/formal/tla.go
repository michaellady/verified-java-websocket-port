package formal

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

var tlaDeclarations = []string{
	"States",
	"MaxCommands",
	"MaxWrites",
	"MaxEvents",
	"vars",
	"Init",
	"CompleteHandshake",
	"EnqueueCommand",
	"ReceiveFrame",
	"ReceiveClose",
	"FlushOutbound",
	"BeginShutdown",
	"DeliverCallback",
	"ApplyBackpressure",
	"FinishClose",
	"Next",
	"TypeOK",
	"QueueBounds",
	"LifecycleMonotonic",
	"ClosedIsTerminal",
	"TerminalDeliveredAtMostOnce",
	"BackpressurePreservesAcceptedWork",
	"Spec",
	"TerminationUnderFairness",
}

var tlaActions = []string{
	"CompleteHandshake",
	"EnqueueCommand",
	"ReceiveFrame",
	"ReceiveClose",
	"FlushOutbound",
	"BeginShutdown",
	"DeliverCallback",
	"ApplyBackpressure",
	"FinishClose",
}

func validateTLA(data []byte) error {
	if bytes.Contains(data, []byte{'\r'}) || bytes.Contains(data, []byte{'\t'}) {
		return fmt.Errorf("TLA+ module must use LF and spaces only")
	}
	text := string(data)
	if strings.Count(text, "MODULE ConnectionModel") != 1 ||
		!strings.HasPrefix(text, "------------------------------ MODULE ConnectionModel ------------------------------\n") {
		return fmt.Errorf("module header must name ConnectionModel exactly once")
	}
	if strings.Count(text, "=====================================================================================") != 1 ||
		!strings.HasSuffix(text, "=====================================================================================\n") {
		return fmt.Errorf("module footer must occur exactly once")
	}
	if !strings.Contains(text, "EXTENDS Naturals, Sequences, FiniteSets") || strings.Contains(text, "EXTENDS TLC") {
		return fmt.Errorf("EXTENDS declaration drifted")
	}
	for _, forbidden := range []string{"Java", "Rust", "payload-byte", "frame-header", "/Users/", "/home/", `C:\\`} {
		if strings.Contains(text, forbidden) {
			return fmt.Errorf("forbidden production or host-specific token %q", forbidden)
		}
	}
	if regexp.MustCompile(`(?i)\bmask\b`).MatchString(text) {
		return fmt.Errorf("model must not contain a mask algorithm")
	}
	if !strings.Contains(text, `States == {"Connecting", "Open", "Closing", "Closed"}`) ||
		!strings.Contains(text, "MaxCommands == 2") ||
		!strings.Contains(text, "MaxWrites == 2") ||
		!strings.Contains(text, "MaxEvents == 2") {
		return fmt.Errorf("state or queue constants drifted")
	}
	wantedVariables := "VARIABLES state, commandQ, writeQ, eventQ, shutdownRequested,\n          terminalQueued, terminalDelivered, backpressureCount"
	wantedVars := "vars == <<state, commandQ, writeQ, eventQ, shutdownRequested,\n          terminalQueued, terminalDelivered, backpressureCount>>"
	if !strings.Contains(text, wantedVariables) || !strings.Contains(text, wantedVars) {
		return fmt.Errorf("variable declaration or vars tuple drifted")
	}
	for _, declaration := range tlaDeclarations {
		expression := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(declaration) + `\s*==`)
		if len(expression.FindAllStringIndex(text, -1)) != 1 {
			return fmt.Errorf("declaration %s must occur exactly once", declaration)
		}
	}
	nextStart := strings.Index(text, "Next ==\n")
	nextEnd := strings.Index(text, "\nTypeOK ==")
	if nextStart < 0 || nextEnd <= nextStart {
		return fmt.Errorf("Next action block is missing")
	}
	actionExpression := regexp.MustCompile(`(?m)^    \\/ ([A-Za-z][A-Za-z0-9]*)$`)
	matches := actionExpression.FindAllStringSubmatch(text[nextStart:nextEnd], -1)
	if len(matches) != len(tlaActions) {
		return fmt.Errorf("Next must contain exactly nine actions")
	}
	for index, action := range tlaActions {
		if matches[index][1] != action {
			return fmt.Errorf("Next action %d is %s, want %s", index, matches[index][1], action)
		}
	}
	for _, required := range []string{
		"/\\ Init",
		"/\\ [][Next]_vars",
		"/\\ WF_vars(CompleteHandshake \\/ BeginShutdown \\/ FinishClose)",
		"/\\ WF_vars(FlushOutbound)",
		"/\\ WF_vars(DeliverCallback)",
		`shutdownRequested => <>(state = "Closed")`,
	} {
		if !strings.Contains(text, required) {
			return fmt.Errorf("required Spec/fairness expression %q is missing", required)
		}
	}
	return nil
}
