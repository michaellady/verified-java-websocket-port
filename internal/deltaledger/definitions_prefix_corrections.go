package deltaledger

// prefixCorrectionDefinitions supersede sequences 14, 15 and 16 without
// rewriting them.
//
// THE DEFECT. Review 01a0464f found that the CLIENT-side handshake budget
// records bound RFC 6455 section 10.4 as though it required a handshake
// budget. Verifying that reading against the authoritative text showed 10.4
// reads "Implementations of WebSocket clients and servers may implement limits
// on the sizes of frames and messages they are willing to accept. This
// specification provides no required minimum size that endpoints are obligated
// to support." — permissive rather than an expectation, and scoped to FRAMES
// AND MESSAGES rather than to the opening handshake. A search of the whole RFC
// found NO clause mandating any limit on the handshake's size, header count or
// header-line length. The client-side records were rebuilt as
// safe-strengthening records on that basis.
//
// The same wrong basis sits in the frozen prefix, at sequences 14, 15 and 16 —
// the SERVER-side budget records for us005.hs.0046, us005.hs.0047 and
// us005.hs.0048. Correcting them in place would rewrite the committed hash
// chain from sequence 14 onward.
//
// THE OWNER RULING. protected/ledger-frozen-prefix-owner-decision-2026-08-28.json
// (sha256 bb3cd0da7f4aed014290dab3dc35b2ec87f41d3d7e7a8c7449816159e9d837c7,
// recomputed at read; decided 2026-08-28T12:54:30Z) rules SUPERSEDE, DO NOT
// REWRITE: append correction records naming what each superseded record got
// wrong and binding the corrected basis, leaving the frozen prefix
// byte-identical. The reasoning recorded there is the immutable-store sidecar
// pattern this plane already used for the US-009 handoff corrections and the
// attempt-0128 sandbox reconciliation — a wrong record a reader can SEE, with
// its correction attached, is better evidence than a rewrite a reader cannot
// audit, and rewriting sealed evidence is exactly the operation the hash chain
// exists to make detectable.
//
// Appended last so the committed prefix through sequence 35 is unchanged.
func prefixCorrectionDefinitions() []Definition {
	return []Definition{
		prefixCorrection(14, "us005.hs.0046", "limit-total-bytes", "HS_LIMIT_TOTAL_BYTES",
			"org.java-websocket.draft6455.server-handshake.limit-total-bytes.hs0046",
			"delta-0b3b46bc555629de7e873b3210c312d74baebd4314170b0997d4c2fd3537d99e",
			"RFC 6455 section 10.4 expects implementations to enforce implementation-specific limits on handshake "+
				"inputs before committing resources; the corpus expectation rejects the over-budget handshake "+
				"(HS_LIMIT_TOTAL_BYTES).",
			"Java-WebSocket 1.6.0 has no handshake byte limit of any kind: translateHandshakeHttp reads unboundedly "+
				"(Draft.java:70-132) and WebSocketImpl.java:370-387 grows tmpHandshakeBytes without bound, "+
				"reallocating to the exception's preferred size (or capacity+16 when that is zero) and never refusing.",
			"total-bytes", "rust/ws-core/fuzz-seeds/us011/total-limit.hex"),
		prefixCorrection(15, "us005.hs.0047", "limit-header-count", "HS_LIMIT_HEADER_COUNT",
			"org.java-websocket.draft6455.server-handshake.limit-header-count.hs0047",
			"delta-ffc8fa535cdeb82aaedb59919ef6b02f67b19815662737ee837c93eacacbe991",
			"RFC 6455 section 10.4 expects implementations to enforce implementation-specific limits on handshake "+
				"inputs; the corpus expectation rejects the over-count handshake (HS_LIMIT_HEADER_COUNT).",
			"Java-WebSocket 1.6.0 has no header-count limit: the header loop in translateHandshakeHttp "+
				"(Draft.java:113-127) is unbounded, so extra request headers are stored and never consulted.",
			"header-count", "rust/ws-core/fuzz-seeds/us011/count-limit.hex"),
		prefixCorrection(16, "us005.hs.0048", "limit-header-line", "HS_LIMIT_HEADER_LINE_BYTES",
			"org.java-websocket.draft6455.server-handshake.limit-header-line.hs0048",
			"delta-ccbff7cfa1813dadd889b86f540da4328a921a0c93972b172177b323f5f5354f",
			"RFC 6455 section 10.4 expects implementations to enforce implementation-specific limits on handshake "+
				"inputs; the corpus expectation rejects the over-length header line (HS_LIMIT_HEADER_LINE_BYTES).",
			"Java-WebSocket 1.6.0 has no header-line length limit: readLine accumulates into a buffer sized from the "+
				"remaining input and returns only on the CRLF pair (Draft.java:70-87), with no per-line ceiling.",
			"header-line", "rust/ws-core/fuzz-seeds/us011/line-limit.hex"),
	}
}

// frozenPrefixOwnerDecision is the shared citation for the supersede ruling.
const frozenPrefixOwnerDecision = " OWNER DECISION: " +
	"protected/ledger-frozen-prefix-owner-decision-2026-08-28.json (workspace orchestrator protected store, sha256 " +
	"bb3cd0da7f4aed014290dab3dc35b2ec87f41d3d7e7a8c7449816159e9d837c7, recomputed at read; decided " +
	"2026-08-28T12:54:30Z) rules SUPERSEDE, DO NOT REWRITE for this correction: the superseded record stays " +
	"byte-identical in the chain and this record is appended beside it, so the error remains visible next to its " +
	"correction and the hash chain's tamper-evidence is preserved rather than spent."

// prefixCorrection builds one superseding record. It deliberately carries the
// SAFE-STRENGTHENING shape the corrected client-side budget records use, since
// the verified finding is that no RFC clause mandates a handshake budget at
// all — so these were never leniency-emulation records.
func prefixCorrection(sequence int, caseID, family, key, supersededSubject, supersededDeltaID,
	wrongExpectation, javaObservation, suffix, seed string) Definition {
	return Definition{
		Subject: supersededSubject + ".corrected",
		RFCRefs: []string{"rfc6455#section-4.1", "rfc6455#section-4.2.1"},
		RFCExpectation: "CORRECTED BASIS. RFC 6455 imposes NO limit on the opening handshake's total size, header " +
			"count, or header-line length, in either direction. Sections 4.1 and 4.2.1 govern the client's generation " +
			"of the opening handshake and the server's reading and validation of it, and prescribe required fields " +
			"and their values, never a size bound. The only clause in the RFC that speaks about limits is section " +
			"10.4 (Implementation-Specific Limits), which reads in full: \"Implementations of WebSocket clients and " +
			"servers may implement limits on the sizes of frames and messages they are willing to accept. This " +
			"specification provides no required minimum size that endpoints are obligated to support.\" That is " +
			"permissive rather than an expectation, and it is scoped to FRAMES AND MESSAGES, not to the opening " +
			"handshake. A search of the whole RFC finds no clause mandating a handshake budget. The wider HTTP layer " +
			"likewise leaves any field-section bound to the implementation. There is therefore no RFC requirement " +
			"here for shipped Java to fall short of.",
		RFCValue: "no-requirement: the RFC prescribes no handshake head-size, header-count or header-line bound, so " +
			"both an unbounded parser and a budgeted one conform",
		JavaRef: "org.java_websocket.drafts.Draft:translateHandshakeHttp",
		JavaObservation: javaObservation + " FIDELITY EVIDENCE: live handshake exam case " + caseID +
			" (corpora/handshake/cases.jsonl, LIVE_EXECUTED against the pinned Java-WebSocket 1.6.0 jar sha256 " +
			"eae29213..., recorded transcript protected/us005-corpora/live/handshake/transcript.jsonl with " +
			"byte-identical rerun); mapping row evidence/us005-handshake-live-mapping.json direction=client_request " +
			"key=" + key + " (family " + family + ", divergent=true); seed " + seed + ".",
		JavaValue: "unbounded: shipped Java applies no handshake byte, header-count or header-line limit on either " +
			"direction, so the head grows with whatever the peer sends",
		AutobahnRefs: []string{"autobahn-v25.10.1:1.1.1"},
		Rationale: "SUPERSEDING CORRECTION for ledger sequence " + itoa(sequence) + " (" + supersededDeltaID +
			", subject semantic:" + supersededSubject + ":provisional-v1). THE SUPERSEDED RECORD'S BASIS WAS WRONG. " +
			"It bound, verbatim: \"" + wrongExpectation + "\" That is incorrect twice over. First, RFC 6455 section " +
			"10.4 does not \"expect\" anything — it reads \"Implementations of WebSocket clients and servers MAY " +
			"implement limits\", which is permissive. Second, it is scoped to FRAMES AND MESSAGES, not to the opening " +
			"handshake, and no clause anywhere in RFC 6455 mandates a handshake size, header-count or header-line " +
			"limit. The corrected basis is bound in this record's rfc_expectation preimage above. " +
			"WHAT CHANGES AS A RESULT: the superseded record is classed as a leniency divergence, as though shipped " +
			"Java were failing an RFC requirement. It is not. Since the RFC requires no handshake budget, the port " +
			"ADDS one and is STRICTER than shipped Java, which makes this a SAFE STRENGTHENING in the same shape as " +
			"the pre-open refusal record — a bound the port introduces, not an RFC rule Java ignores. " +
			"WHAT THE MAPPING'S rfc_verdict MEANS HERE, stated because it is what misled the original record: " +
			"evidence/us005-handshake-live-mapping.json records rfc_verdict=reject for " + key + ", but that is the " +
			"verdict of the corpus's RFC-DERIVED GO MODEL, which enforces the configured budgets. It is not an RFC " +
			"mandate. WHAT DOES NOT CHANGE: the recorded Java behaviour, the live evidence, the corpus case and the " +
			"port's behaviour are all exactly as the superseded record described — only the normative framing is " +
			"corrected. The port still retains the configured budget deliberately, under the AC-amendment's rule that " +
			"checked config limits are not relaxed. WS_CORE SITE: rust/ws-core/src/handshake/server.rs routes every " +
			"chunk through HeadAccumulator::push (rust/ws-core/src/handshake/http.rs), which checks the total-byte, " +
			"header-line and header-count budgets BEFORE buffering each byte; pinned by " +
			"rust/ws-core/tests/handshake_server.rs::configured_budgets_refuse_with_the_named_limit. SCOPE NOTE: this " +
			"record corrects the NORMATIVE BASIS only. It does not withdraw the superseded record, which remains in " +
			"the chain at sequence " + itoa(sequence) + " with its digest intact." +
			frozenPrefixOwnerDecision + ownerDecision,
	}
}

// itoa renders a small non-negative sequence number without pulling strconv
// into this file's import set for a single use.
func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits []byte
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}
