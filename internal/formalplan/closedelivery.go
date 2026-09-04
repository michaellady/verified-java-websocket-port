// US-006 reality-check round 1, BLOCKING-1(d): cross-artifact close-delivery
// consistency. The merged US-006 lanes once contradicted each other — lane A's
// proof target truthfully recorded AT-LEAST-ONCE terminal callback delivery
// under listener re-entry (shipped Java fires onWebsocketClose at
// WebSocketImpl.java:557 BEFORE readyState = CLOSED at 566 under the reentrant
// monitor at 530), while the connection model, backend qualification, and
// concurrency plan still attributed exactly-once delivery to the Java monitor.
// This check makes that inconsistency class a typed blocking regression:
//
//   - CLOSE_DELIVERY_TRUTH_ANCHOR_MISSING: the proof-targets record for
//     formal.close.terminal-absorbing no longer states the shipped
//     at-least-once-under-re-entry truth.
//   - MODEL_REENTRANCY_RESTRICTION_UNDECLARED: connection-model.tla no longer
//     declares the no-listener-re-entrancy restriction that scopes its
//     exactly-once invariants.
//   - JAVA_EXACTLY_ONCE_TERMINAL_CLAIM: an artifact claims Java-attributed
//     exactly-once TERMINAL delivery without scoping it to the declared model
//     restriction or marking it as the port-side strengthening
//     (note.close.exactly-once-terminal-delivery, pending its behavior-delta
//     ledger entry).
//
// HONESTY BOX: the claim scan is a lexical tripwire over prose, not a
// semantic prover. It flags a string only when an exactly-once claim, a
// terminal-delivery marker, and a Java-attribution marker co-occur with none
// of the sanctioned scoping markers; carefully-worded dishonesty can evade
// it, and the review process remains the backstop. Its purpose is to make the
// KNOWN regression — restoring the pre-reconciliation wording — loud.
package formalplan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	vendorprotocol "github.com/michaellady/verified-java-to-rust/foundation/protocol"
)

const (
	cdTruthAnchorTargetID = "target.formal.close.terminal-absorbing"

	CDFindingTruthAnchorMissing    = "CLOSE_DELIVERY_TRUTH_ANCHOR_MISSING"
	CDFindingRestrictionUndeclared = "MODEL_REENTRANCY_RESTRICTION_UNDECLARED"
	CDFindingJavaExactlyOnceClaim  = "JAVA_EXACTLY_ONCE_TERMINAL_CLAIM"
)

// cdExcuseMarkers are the sanctioned scoping markers: a string that carries
// any of them alongside an exactly-once claim is stating (or contrasting
// against) the reconciled truth rather than restoring the false parity claim.
var cdExcuseMarkers = []string{
	"at-least-once", "at least once",
	"reentr", "re-enter", "re-entry", "re-entranc",
	"restriction",
	"strengthening", "port-side",
}

var cdJavaAttributionMarkers = []string{
	"java", "monitor", "l2", "websocketimpl", "closeconnection",
}

// cdClaimsJavaExactlyOnceTerminal reports whether one prose string claims
// Java-attributed exactly-once terminal delivery without any sanctioned
// scoping marker.
func cdClaimsJavaExactlyOnceTerminal(text string) bool {
	lowered := strings.ToLower(text)
	if !strings.Contains(lowered, "exactly-once") && !strings.Contains(lowered, "exactly once") {
		return false
	}
	if !strings.Contains(lowered, "terminal") && !strings.Contains(lowered, "onwebsocketclose") {
		return false
	}
	attributed := false
	for _, marker := range cdJavaAttributionMarkers {
		if strings.Contains(lowered, marker) {
			attributed = true
			break
		}
	}
	if !attributed {
		return false
	}
	for _, marker := range cdExcuseMarkers {
		if strings.Contains(lowered, marker) {
			return false
		}
	}
	return true
}

// cdScanJSONStrings walks a decoded JSON document and reports the paths of
// every string value that claims Java-attributed exactly-once terminal
// delivery.
func cdScanJSONStrings(node any, jsonPath string, offending *[]string) {
	switch value := node.(type) {
	case string:
		if cdClaimsJavaExactlyOnceTerminal(value) {
			*offending = append(*offending, jsonPath)
		}
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys) // deterministic order for deterministic verdicts
		for _, key := range keys {
			cdScanJSONStrings(value[key], jsonPath+"."+key, offending)
		}
	case []any:
		for index, child := range value {
			cdScanJSONStrings(child, fmt.Sprintf("%s[%d]", jsonPath, index), offending)
		}
	}
}

// cdCommentBlocks groups a TLA+ artifact's comment text into contiguous
// blocks (consecutive lines carrying \* comment content), so a claim and its
// scoping marker written across adjacent lines are judged together.
func cdCommentBlocks(text string) []struct {
	StartLine int
	Text      string
} {
	var blocks []struct {
		StartLine int
		Text      string
	}
	var current []string
	currentStart := 0
	flush := func() {
		if len(current) > 0 {
			blocks = append(blocks, struct {
				StartLine int
				Text      string
			}{currentStart, strings.Join(current, " ")})
			current = nil
		}
	}
	for index, line := range strings.Split(text, "\n") {
		marker := strings.Index(line, `\*`)
		if marker < 0 {
			flush()
			continue
		}
		if len(current) == 0 {
			currentStart = index + 1
		}
		current = append(current, strings.TrimSpace(line[marker+2:]))
	}
	flush()
	return blocks
}

// evaluateCloseDeliveryConsistency runs the cross-artifact check over
// whichever artifacts are present in the tree; absent artifacts are already
// blocked by their own absence findings.
func evaluateCloseDeliveryConsistency(evaluation *formalEvaluation) {
	// (1) The proof-targets truth anchor must stay present: the
	// terminal-absorbing record must state the shipped at-least-once
	// semantics under listener re-entry.
	if content, present := evaluation.readFile(ProofTargetsDocumentPath); present {
		var document ProofTargetsDocument
		if json.Unmarshal(content, &document) == nil && len(document.Targets) > 0 {
			anchorFound := false
			for _, target := range document.Targets {
				if target.TargetID != cdTruthAnchorTargetID {
					continue
				}
				anchorFound = true
				lowered := strings.ToLower(target.Statement)
				if !strings.Contains(lowered, "at-least-once") || !strings.Contains(lowered, "reentr") {
					evaluation.add(CDFindingTruthAnchorMissing, vendorprotocol.Block,
						ProofTargetsDocumentPath, "$.targets."+cdTruthAnchorTargetID+".statement",
						"the terminal-absorbing proof target no longer records the shipped truth: at-least-once terminal delivery under listener re-entry (onWebsocketClose at WebSocketImpl.java:557 before CLOSED at 566 under the reentrant monitor at 530)")
				}
			}
			if !anchorFound {
				evaluation.add(CDFindingTruthAnchorMissing, vendorprotocol.Block,
					ProofTargetsDocumentPath, "$.targets",
					"proof target "+cdTruthAnchorTargetID+" is missing; the close-delivery truth anchor must exist")
			}
		}
		var generic any
		if json.Unmarshal(content, &generic) == nil {
			var offending []string
			cdScanJSONStrings(generic, "$", &offending)
			for _, path := range offending {
				evaluation.add(CDFindingJavaExactlyOnceClaim, vendorprotocol.Block,
					ProofTargetsDocumentPath, path,
					"string claims Java-attributed exactly-once terminal delivery without the declared no-re-entrancy scoping; shipped Java is at-least-once under listener re-entry")
			}
		}
	}

	// (2) The connection model must declare its no-listener-re-entrancy
	// restriction and state the shipped at-least-once contrast, and its
	// comments may not claim unscoped Java exactly-once terminal delivery.
	if raw, err := os.ReadFile(filepath.Join(evaluation.root, filepath.FromSlash(ConnectionModelTLAPath))); err == nil {
		text := string(raw)
		lowered := strings.ToLower(text)
		if !strings.Contains(lowered, "listener re-entrancy") || !strings.Contains(lowered, "at-least-once") {
			evaluation.add(CDFindingRestrictionUndeclared, vendorprotocol.Block,
				ConnectionModelTLAPath, "",
				"the model must declare its no-listener-re-entrancy restriction in the MODEL SCOPE header and state that shipped Java is at-least-once under listener re-entry; without the declaration its exactly-once invariants read as claims about unrestricted Java")
		}
		for _, block := range cdCommentBlocks(text) {
			if cdClaimsJavaExactlyOnceTerminal(block.Text) {
				evaluation.add(CDFindingJavaExactlyOnceClaim, vendorprotocol.Block,
					ConnectionModelTLAPath, fmt.Sprintf("comment-block-at-line-%d", block.StartLine),
					"model comment claims Java-attributed exactly-once terminal delivery without the declared no-re-entrancy scoping; shipped Java is at-least-once under listener re-entry")
			}
		}
	}

	// (3) The backend qualification and concurrency plan may not attribute
	// exactly-once terminal delivery to Java without scoping.
	for _, docPath := range []string{BackendQualificationDocumentPath, ConcurrencyPlanDocumentPath} {
		content, present := evaluation.readFile(docPath)
		if !present {
			continue
		}
		var generic any
		if json.Unmarshal(content, &generic) != nil {
			continue // FORMAL_DOCUMENT_INVALID already blocks
		}
		var offending []string
		cdScanJSONStrings(generic, "$", &offending)
		for _, path := range offending {
			evaluation.add(CDFindingJavaExactlyOnceClaim, vendorprotocol.Block,
				docPath, path,
				"string claims Java-attributed exactly-once terminal delivery without the declared no-re-entrancy scoping; the exactly-once obligation is a port-side strengthening (note.close.exactly-once-terminal-delivery, pending its behavior-delta ledger entry), never a Java parity fact")
		}
	}
}
