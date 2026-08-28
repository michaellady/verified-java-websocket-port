// Package deltaledger holds the recorded Java-vs-RFC behavior divergences of
// the pinned Java-WebSocket 1.6.0 runtime and builds them into the
// hash-chained behavior-delta ledger records committed at
// evidence/java/behavior-delta-ledger.json.
//
// Mandate: the owner AC-amendment decision (workspace protected store,
// us010-016-ac-amendment-owner-decision-2026-08-27.json, sha256
// 26849b5ea74006504d18507ac694c00e882e7fd37d4cd8c8502ea824e96ea974) amends the
// US-010..US-016 acceptance criteria to the JAVA_FAITHFUL_PLUS_SAFE fidelity
// authority and makes ledgering every recorded Java-vs-RFC divergence
// mandatory before story acceptance.
//
// Every definition below is sourced from recorded evidence only: the US-005
// live handshake exam (16 live-recorded RFC-reject-but-Java-accept sites,
// evidence/us005-handshake-live-mapping.json + corpora/handshake/cases.jsonl),
// the batch-A framing corrections and the batch-C close/control corrections
// (workspace protected borrow-receipt-batch-{a,c}.json; batch-C also in-repo at
// drafts/borrow-receipt-batch-c.json), the reference model
// internal/corpora/derive.go, and the live-oracle confirmation of the 74-case
// public corpus (protected us-live-oracle-confirmation-receipt.json:
// 74/74 live-Java confirmed, 0 behavioral Rust-vs-live-Java divergences).
//
// The ledger's frozen 1.0.0 vocabulary (schemas/
// behavior-delta-ledger-1.0.0.schema.json) predates the owner amendment:
// normative_authority is the constant "rfc6455" and disposition admits only
// "unresolved" or "rfc-governs". Records therefore carry disposition
// "unresolved" — the divergence is deliberately retained under the owner's
// JAVA_FAITHFUL_PLUS_SAFE decision, not resolved toward the RFC — with the
// owner-decision citation in every rationale.
package deltaledger

// Definition is one recorded Java-vs-RFC divergence. The *Observation and
// *Value strings are the exact digest preimages bound into the ledger record
// (rfc_expectation_digest, rfc_value_digest, java_observation_digest,
// java_value_digest); regenerating the ledger from these definitions
// reproduces the committed record chain byte-for-byte.
type Definition struct {
	// Subject is the semantic subject reference (without the trailing
	// ":provisional-v1", which the builder appends).
	Subject string
	// RFCRefs are the RFC 6455 clause anchors (builder sorts them).
	RFCRefs []string
	// RFCExpectation is the digest preimage describing what the RFC requires.
	RFCExpectation string
	// RFCValue is the normalized RFC-expected observable (digest preimage).
	RFCValue string
	// JavaRef is the pinned Java entity, "org.java_websocket.Class:member".
	JavaRef string
	// JavaObservation is the digest preimage describing the recorded pinned
	// Java behavior with its exact evidence sources.
	JavaObservation string
	// JavaValue is the normalized observed Java observable (digest preimage).
	JavaValue string
	// AutobahnRefs are nominal Autobahn case anchors (builder sorts them).
	// No Autobahn execution exists on this plane; see AutobahnResultMarker.
	AutobahnRefs []string
	// AutobahnResult overrides AutobahnResultMarker for the records whose
	// Autobahn refs ARE executed observations rather than nominal anchors
	// (the E5 fuzzingclient leg against ws-testee, merged at commit
	// 76158f35, plus the recovered Java server-mode qualification receipt).
	// Empty means the honest non-execution marker.
	AutobahnResult string
	// AutobahnValue overrides AutobahnValueMarker on those same records.
	// Empty means the unobserved marker.
	AutobahnValue string
	// Rationale is the bounded free-text record rationale: divergence,
	// fidelity evidence, ws_core implementation site, safety note, and the
	// owner-decision citation.
	Rationale string
}

// AutobahnResultMarker is the digest preimage for autobahn_result_digest on
// every record. It is an honest non-execution marker, never an observation:
// evidence/java/autobahn-baseline.json is status BLOCKED with 0/247 cases
// executed in both modes and rerun disposition NO_FURTHER_RERUNS_AUTHORIZED.
const AutobahnResultMarker = "AUTOBAHN_NOT_EXECUTED: evidence/java/autobahn-baseline.json status=BLOCKED; " +
	"client and server modes each 0/247 selected cases executed; rerun disposition NO_FURTHER_RERUNS_AUTHORIZED; " +
	"the autobahn_refs on this record are nominal case anchors for the divergence domain, not executed observations."

// AutobahnValueMarker is the digest preimage for autobahn_value_digest on
// every record: no Autobahn value was ever observed on this plane.
const AutobahnValueMarker = "AUTOBAHN_VALUE_UNOBSERVED"

// ownerDecision is the shared owner-decision citation appended to every
// rationale.
const ownerDecision = " OWNER DECISION: us010-016-ac-amendment-owner-decision-2026-08-27.json " +
	"(workspace orchestrator protected store, sha256 26849b5ea74006504d18507ac694c00e882e7fd37d4cd8c8502ea824e96ea974, " +
	"decided 2026-08-27T21:42:50Z) binds the US-010..US-016 ACs to the recorded fidelity authority and mandates this record; " +
	"disposition is 'unresolved' because the frozen 1.0.0 vocabulary has no java-faithful term — the divergence is deliberately " +
	"retained under JAVA_FAITHFUL_PLUS_SAFE, not resolved toward the RFC. AUTOBAHN: leg not executed (baseline BLOCKED 0/247, " +
	"NO_FURTHER_RERUNS_AUTHORIZED); refs are nominal anchors."

// liveExamEvidence is the shared live handshake exam evidence citation.
const liveExamEvidence = "FIDELITY EVIDENCE: live handshake exam case %CASE% (corpora/handshake/cases.jsonl, LIVE_EXECUTED " +
	"against the pinned Java-WebSocket 1.6.0 jar sha256 eae29213..., recorded transcript protected/us005-corpora/live/handshake/" +
	"transcript.jsonl with byte-identical rerun; batch-B direct per-case differential 49/49 identical, batch-C regression 49/49); " +
	"mapping row evidence/us005-handshake-live-mapping.json"

// handshakeSafety is the shared safety note for server-handshake records.
const handshakeSafety = " SAFETY: acceptance is bounded by the configured handshake budgets (HeadAccumulator allocates " +
	"budget-before-buffer; rust/ws-core/tests/handshake_server.rs::configured_budgets_refuse_with_the_named_limit) under " +
	"forbid(unsafe_code); no unchecked allocation or panic path is introduced by emulating the accept."

func handshakeDefinition(caseID, family, subject, javaRef, rfcExpectation, javaObservation, rationale string, rfcRefs []string) Definition {
	return Definition{
		Subject:        subject,
		RFCRefs:        rfcRefs,
		RFCExpectation: rfcExpectation,
		RFCValue:       "reject: refuse the opening handshake (HTTP error; the connection never reaches Open)",
		JavaRef:        javaRef,
		JavaObservation: javaObservation + " " +
			replaceCase(liveExamEvidence, caseID) + " (family " + family + ", divergent=true).",
		JavaValue:    "accept: 101 Switching Protocols with the derived Sec-WebSocket-Accept; the connection opens",
		AutobahnRefs: []string{"autobahn-v25.10.1:1.1.1"},
		Rationale: "DIVERGENCE (" + family + ", live case " + caseID + "): " + rationale +
			" WS_CORE SITE: rust/ws-core/src/handshake/server.rs + rust/ws-core/src/handshake/http.rs implement the shipped " +
			"Java accept predicate (HTTP-version-13 plus non-empty Sec-WebSocket-Key only; quirks Q1-Q8 per the module doc)." +
			handshakeSafety + ownerDecision,
	}
}

func replaceCase(template, caseID string) string {
	out := ""
	for i := 0; i < len(template); {
		if i+6 <= len(template) && template[i:i+6] == "%CASE%" {
			out += caseID
			i += 6
			continue
		}
		out += string(template[i])
		i++
	}
	return out
}

// Definitions returns every recorded Java-vs-RFC divergence in ledger append
// order: 16 live handshake-exam divergences, 8 framing divergences from the
// batch-A corrections, and 8 close/control divergences from the batch-C
// corrections.
func Definitions() []Definition {
	definitions := handshakeDefinitions()
	definitions = append(definitions, framingDefinitions()...)
	definitions = append(definitions, closeControlDefinitions()...)
	// Appended last so the committed hash chain's existing prefix is
	// unchanged by the E5/E5b Autobahn follow-ups.
	definitions = append(definitions, autobahnCompositionDefinitions()...)
	// Appended last for the same reason: the owner-mandated
	// rejected-close-transition record must not disturb the committed
	// 34-record prefix.
	definitions = append(definitions, closeTransitionDefinitions()...)
	// Appended last for the same reason again: the G3c/G3d/G3e gap-closure
	// records must not disturb the committed 35-record prefix.
	definitions = append(definitions, gapClosureDefinitions()...)
	// Appended last for the same reason again: the owner-ruled superseding
	// corrections for sequences 14-16 must not disturb the frozen prefix
	// they correct (protected/ledger-frozen-prefix-owner-decision-2026-08-28.json,
	// sha256 bb3cd0da7f4aed01...: SUPERSEDE, DO NOT REWRITE).
	definitions = append(definitions, prefixCorrectionDefinitions()...)
	return definitions
}

func handshakeDefinitions() []Definition {
	acceptServer := "org.java_websocket.drafts.Draft_6455:acceptHandshakeAsServer"
	generateFinalKey := "org.java_websocket.drafts.Draft_6455:generateFinalKey"
	translateHTTP := "org.java_websocket.drafts.Draft:translateHandshakeHttp"
	readLine := "org.java_websocket.drafts.Draft:readLine"
	section41 := []string{"rfc6455#section-4.1", "rfc6455#section-4.2.1"}
	section421 := []string{"rfc6455#section-4.2.1"}
	section104 := []string{"rfc6455#section-10.4"}

	neverExamined := "The Java server handshake never evaluates this rule: acceptHandshakeAsServer checks only " +
		"Sec-WebSocket-Version == 13 (Draft_6455.java:262-286) and postProcessHandshakeResponseAsServer requires only a " +
		"non-empty key (Draft_6455.java:432-441); the request is accepted with the derived accept value."

	return []Definition{
		handshakeDefinition("us005.hs.0013", "missing-host",
			"org.java-websocket.draft6455.server-handshake.missing-host.hs0013", acceptServer,
			"RFC 6455 section 4.1 requires the client opening handshake to contain a Host header field and section 4.2.1 "+
				"requires the server to read and validate the client handshake, returning an HTTP error when it is invalid.",
			neverExamined,
			"the RFC requires a Host header; the live pinned Java server accepted the request with no Host header "+
				"(never examined). Pinned by rust/ws-core/tests/handshake_server.rs::missing_host_upgrade_connection_and_their_values_are_never_examined.",
			section41),
		handshakeDefinition("us005.hs.0014", "missing-upgrade",
			"org.java-websocket.draft6455.server-handshake.missing-upgrade.hs0014", acceptServer,
			"RFC 6455 section 4.1/4.2.1 requires an Upgrade header field containing the value 'websocket'; a handshake "+
				"without it must be refused.",
			neverExamined,
			"the RFC requires an Upgrade: websocket header; the live pinned Java server accepted the request with no "+
				"Upgrade header (never examined). Pinned by rust/ws-core/tests/handshake_server.rs::missing_host_upgrade_connection_and_their_values_are_never_examined.",
			section41),
		handshakeDefinition("us005.hs.0015", "upgrade-value",
			"org.java-websocket.draft6455.server-handshake.upgrade-value.hs0015", acceptServer,
			"RFC 6455 section 4.2.1 requires the Upgrade header field's value to case-insensitively equal 'websocket'; "+
				"any other value must be refused.",
			neverExamined,
			"the RFC requires Upgrade to equal 'websocket'; the live pinned Java server accepted a request whose Upgrade "+
				"value is wrong (the value is never examined). Same never-examined predicate as us005.hs.0013.",
			section421),
		handshakeDefinition("us005.hs.0016", "missing-connection",
			"org.java-websocket.draft6455.server-handshake.missing-connection.hs0016", acceptServer,
			"RFC 6455 section 4.1/4.2.1 requires a Connection header field whose value includes the 'Upgrade' token; a "+
				"handshake without it must be refused.",
			neverExamined,
			"the RFC requires a Connection: Upgrade header; the live pinned Java server accepted the request with no "+
				"Connection header (never examined). Pinned by rust/ws-core/tests/handshake_server.rs::missing_host_upgrade_connection_and_their_values_are_never_examined.",
			section41),
		handshakeDefinition("us005.hs.0017", "connection-value",
			"org.java-websocket.draft6455.server-handshake.connection-value.hs0017", acceptServer,
			"RFC 6455 section 4.2.1 requires the Connection header field's value to include the 'Upgrade' token; any "+
				"other value must be refused.",
			neverExamined,
			"the RFC requires the Connection value to include 'Upgrade'; the live pinned Java server accepted a request "+
				"whose Connection value is wrong (the value is never examined). Same never-examined predicate as us005.hs.0013.",
			section421),
		handshakeDefinition("us005.hs.0019", "key-not-base64",
			"org.java-websocket.draft6455.server-handshake.key-not-base64.hs0019", generateFinalKey,
			"RFC 6455 section 4.2.1 item 5 requires Sec-WebSocket-Key to be a base64-encoded value that, when decoded, is "+
				"16 bytes; a non-base64 key must be refused.",
			"generateFinalKey (Draft_6455.java:832-841) SHA-1 hashes any non-empty header string after String.trim; the key "+
				"encoding is never validated, so a non-base64 key is accepted and the accept value hashes the malformed key.",
			"the RFC requires a base64 16-byte key; the live pinned Java server accepted a non-base64 key and derived the "+
				"accept from the raw string. Pinned by rust/ws-core/tests/handshake_server.rs::non_base64_and_wrong_length_keys_are_hashed_as_is; "+
				"seed rust/ws-core/fuzz-seeds/us011/noncanonical-key.hex.",
			section421),
		handshakeDefinition("us005.hs.0020", "key-not-base64",
			"org.java-websocket.draft6455.server-handshake.key-not-base64.hs0020", generateFinalKey,
			"RFC 6455 section 4.2.1 item 5 requires Sec-WebSocket-Key to be a base64-encoded value that, when decoded, is "+
				"16 bytes; a non-base64 key must be refused.",
			"generateFinalKey (Draft_6455.java:832-841) SHA-1 hashes any non-empty header string after String.trim; the key "+
				"encoding is never validated. Second recorded input shape of the key-not-base64 family (distinct wire bytes from us005.hs.0019).",
			"second live-recorded key-not-base64 input shape; same never-validated predicate and ws_core site as us005.hs.0019.",
			section421),
		handshakeDefinition("us005.hs.0021", "key-wrong-length",
			"org.java-websocket.draft6455.server-handshake.key-wrong-length.hs0021", generateFinalKey,
			"RFC 6455 section 4.2.1 item 5 requires the decoded Sec-WebSocket-Key to be exactly 16 bytes; a key of any "+
				"other decoded length must be refused.",
			"The decoded key length is never validated: generateFinalKey hashes the raw header string "+
				"(Draft_6455.java:832-841), so a key whose decoded length is not 16 bytes is accepted.",
			"the RFC requires a decoded 16-byte key; the live pinned Java server accepted a wrong-length key. Pinned by "+
				"rust/ws-core/tests/handshake_server.rs::non_base64_and_wrong_length_keys_are_hashed_as_is; seed rust/ws-core/fuzz-seeds/us011/wrong-key-length.hex.",
			section421),
		handshakeDefinition("us005.hs.0022", "key-wrong-length",
			"org.java-websocket.draft6455.server-handshake.key-wrong-length.hs0022", generateFinalKey,
			"RFC 6455 section 4.2.1 item 5 requires the decoded Sec-WebSocket-Key to be exactly 16 bytes; a key of any "+
				"other decoded length must be refused.",
			"The decoded key length is never validated (Draft_6455.java:832-841). Second recorded input shape of the "+
				"key-wrong-length family (distinct wire bytes from us005.hs.0021).",
			"second live-recorded key-wrong-length input shape; same never-validated predicate and ws_core site as us005.hs.0021.",
			section421),
		handshakeDefinition("us005.hs.0027", "duplicate-header",
			"org.java-websocket.draft6455.server-handshake.duplicate-header.hs0027", translateHTTP,
			"RFC 6455 section 4.2.1 requires validating the handshake as an HTTP request; RFC 9110 section 5.3 forbids "+
				"generating/consuming a duplicated singleton field such as Sec-WebSocket-Key as one combined value, so a "+
				"duplicated key must be refused.",
			"translateHandshakeHttp joins duplicated header values with '; ' (Draft.java:119-125); a duplicated "+
				"Sec-WebSocket-Key is accepted with the accept value computed over the joined string.",
			"the RFC-derived model rejects the duplicated Sec-WebSocket-Key; the live pinned Java server joined the values "+
				"and accepted (mapping note: the duplicated-Version sibling instead rejects NOT_MATCHED). Pinned by "+
				"rust/ws-core/tests/handshake_server.rs::duplicated_key_joins_and_hashes_the_joined_string and "+
				"::duplicated_version_joins_to_an_unparseable_value_and_rejects_not_matched.",
			section421),
		handshakeDefinition("us005.hs.0029", "header-name-not-token",
			"org.java-websocket.draft6455.server-handshake.header-name-not-token.hs0029", translateHTTP,
			"RFC 6455 section 4.2.1 requires the handshake to be a valid HTTP request; RFC 9112 section 5 requires header "+
				"field names to be HTTP tokens, so a non-token field name makes the message invalid and must be refused.",
			"Java performs no header-name token validation: translateHandshakeHttp stores any name up to the first colon "+
				"(Draft.java:115-125); the request is accepted when the remaining checks pass.",
			"the RFC-derived model rejects a non-token header name; the live pinned Java server accepted it. Pinned by "+
				"rust/ws-core/tests/handshake_server.rs::header_names_are_never_token_validated; seed rust/ws-core/fuzz-seeds/us011/invalid-header-name.hex.",
			section421),
		handshakeDefinition("us005.hs.0030", "header-name-not-token",
			"org.java-websocket.draft6455.server-handshake.header-name-not-token.hs0030", translateHTTP,
			"RFC 6455 section 4.2.1 requires the handshake to be a valid HTTP request; RFC 9112 section 5 requires header "+
				"field names to be HTTP tokens, so a non-token field name makes the message invalid and must be refused.",
			"Java performs no header-name token validation (Draft.java:115-125). Second recorded input shape of the "+
				"header-name-not-token family (distinct wire bytes from us005.hs.0029).",
			"second live-recorded non-token header-name input shape; same never-validated predicate and ws_core site as us005.hs.0029.",
			section421),
		handshakeDefinition("us005.hs.0034", "bare-lf",
			"org.java-websocket.draft6455.server-handshake.bare-lf.hs0034", readLine,
			"RFC 6455 section 4.2.1 requires the handshake to be a valid HTTP request; RFC 9112 section 2.2 terminates "+
				"lines with CRLF and forbids a bare LF as a line terminator, so the message is malformed and must be refused.",
			"Draft.readLine terminates only on CRLF (Draft.java:78), so a bare-LF line folds into the following "+
				"CRLF-terminated line as one header; the surviving fields decide the observable and the request is accepted.",
			"the RFC-derived model rejects the bare-LF line; the live pinned Java server folded it and accepted. Pinned by "+
				"rust/ws-core/tests/handshake_server.rs::bare_lf_folds_into_the_next_line_and_still_accepts; seed rust/ws-core/fuzz-seeds/us011/bare-lf.hex.",
			section421),
		handshakeDefinition("us005.hs.0046", "limit-total-bytes",
			"org.java-websocket.draft6455.server-handshake.limit-total-bytes.hs0046", translateHTTP,
			"RFC 6455 section 10.4 expects implementations to enforce implementation-specific limits on handshake inputs "+
				"before committing resources; the corpus expectation rejects the over-budget handshake (HS_LIMIT_TOTAL_BYTES).",
			"Java-WebSocket 1.6.0 has no handshake byte limit of any kind: translateHandshakeHttp reads unboundedly "+
				"(Draft.java:70-132) and WebSocketImpl.java:370-387 grows tmpHandshakeBytes without bound; the over-budget "+
				"request is accepted when the remaining checks pass.",
			"the RFC-derived model rejects the over-budget handshake; the live pinned Java server (which has no limits) "+
				"accepted it. ws_core retains CONFIGURED handshake budgets as a hard safety ceiling (JAVA_FAITHFUL_PLUS_SAFE: "+
				"Java's unbounded growth is NOT emulated) while the live-exam input fits the configured budget and accepts "+
				"exactly as live Java did; seed rust/ws-core/fuzz-seeds/us011/total-limit.hex.",
			section104),
		handshakeDefinition("us005.hs.0047", "limit-header-count",
			"org.java-websocket.draft6455.server-handshake.limit-header-count.hs0047", translateHTTP,
			"RFC 6455 section 10.4 expects implementations to enforce implementation-specific limits on handshake inputs; "+
				"the corpus expectation rejects the over-count handshake (HS_LIMIT_HEADER_COUNT).",
			"Java-WebSocket 1.6.0 has no header-count limit: translateHandshakeHttp loops over headers unboundedly "+
				"(Draft.java:70-132); the request is accepted when the remaining checks pass.",
			"the RFC-derived model rejects the over-count handshake; the live pinned Java server (no limits) accepted it. "+
				"ws_core retains the configured header-count budget as the safety ceiling (JAVA_FAITHFUL_PLUS_SAFE); the "+
				"live-exam input fits the budget and accepts exactly as live Java did; seed rust/ws-core/fuzz-seeds/us011/count-limit.hex.",
			section104),
		handshakeDefinition("us005.hs.0048", "limit-header-line",
			"org.java-websocket.draft6455.server-handshake.limit-header-line.hs0048", translateHTTP,
			"RFC 6455 section 10.4 expects implementations to enforce implementation-specific limits on handshake inputs; "+
				"the corpus expectation rejects the over-length header line (HS_LIMIT_HEADER_LINE_BYTES).",
			"Java-WebSocket 1.6.0 has no header-line length limit: readLine accumulates until CRLF without bound "+
				"(Draft.java:70-132); the request is accepted when the remaining checks pass.",
			"the RFC-derived model rejects the over-length header line; the live pinned Java server (no limits) accepted "+
				"it. ws_core retains the configured line budget as the safety ceiling (JAVA_FAITHFUL_PLUS_SAFE); the "+
				"live-exam input fits the budget and accepts exactly as live Java did; seed rust/ws-core/fuzz-seeds/us011/line-limit.hex.",
			section104),
	}
}
