package deltaledger

// THE RULING THAT CLOSES F010, AS A LEDGER APPEND RATHER THAN AN EDIT.
//
// Sequence 58 superseded sequence 55 because 55's DESCRIPTION OF THE PORT had
// become false. It kept `unresolved`, and it said in its own hashed bytes why:
// US-011 AC2 forbids the two fields the port now emits, that conflict is
// between the PORT and a PROJECT SPECIFICATION, and this ledger's authority
// model has one normative pole plus three observation sources with no field for
// a project criterion. So it stated the conflict and named the ruling owed.
//
// THE RULING CAME, AND IT DOES NOT CHANGE ONE FACT IN SEQUENCE 58. Every
// measurement that record binds is still true: the port emits five fields in
// String.CASE_INSENSITIVE_ORDER, byte-exact against the pinned jar's own
// output, and RFC 6455 4.2.2 still does not determine the observable. What
// moved is the DISPOSITION, and only the disposition — from `unresolved`,
// which asserted an open question, to `adopt-java`, which asserts a licensed
// adoption. That is exactly the shape the supersession machinery exists for:
// the ledger is append-only with a frozen prefix through sequence 35, the owner
// ruling at protected/ledger-frozen-prefix-owner-decision-2026-08-28.json is
// SUPERSEDE, DO NOT REWRITE, and a disposition is not a typo to be corrected in
// place. Sequence 58 stays byte-identical in the chain with its digest intact,
// and the record that answers its question is appended beside it.
//
// WHY THE MISMATCH CLASS DOES NOT MOVE WITH THE DISPOSITION, which is the one
// thing a reader is most likely to expect to move. F013 is the finding: the
// class describes WHERE THE MISMATCH LIVES, not what the port should do about
// it. RFC 6455 4.2.2 LISTS the fields the 101 response is required to carry and
// says nothing about whether ADDITIONAL fields may appear, so the RFC genuinely
// does not settle this observable — that was true while the disposition was
// `unresolved` and it is still true now that a project-level authority has
// settled what to DO. Moving the class to `java-quirk` would assert the RFC
// determines the observable and Java is on the wrong side of it, and there is
// no side to be on; moving it to `rust-defect` would assert the port is wrong,
// which the ruling says it is not. `underspecified-behavior` is the class the
// evidence supports before and after the ruling, and this record says so in its
// own hashed bytes rather than leaving the reader to assume the pair moves
// together.
//
// APPENDED LAST so every existing record keeps its sequence, previous_digest
// and record_digest.

func ac2BannerRulingDefinitions() []Definition {
	return []Definition{serverResponseFieldsAdoption()}
}

// serverResponseFieldsAdoption supersedes sequence 58.
func serverResponseFieldsAdoption() Definition {
	return Definition{
		Subject: "org.java-websocket.draft6455.server-handshake.response-server-and-date-fields.adopted",
		Supersedes: []Supersession{{
			Sequence: 58,
			DeltaID:  "delta-b0350fc5055f1a66e894ef34547f8cc7c6c40382e353c1ea752b12c8801bfa55",
			Subject:  "org.java-websocket.draft6455.server-handshake.response-server-and-date-fields.corrected",
			Reason:   "the-disposition-it-holds-open-was-already-ruled-and-the-owner-confirmed-the-reading-on-2026-09-04",
			Authority: "protected/ledger-frozen-prefix-owner-decision-2026-08-28.json" +
				"@sha256:bb3cd0da7f4aed014290dab3dc35b2ec87f41d3d7e7a8c7449816159e9d837c7",
		}},
		RFCRefs: []string{"rfc6455#section-4.2.2"},
		RFCExpectation: "RFC 6455 section 4.2.2 ENUMERATES the fields the server's 101 response is required to " +
			"carry — Upgrade, Connection and Sec-WebSocket-Accept — and states no rule about whether ADDITIONAL " +
			"header fields may appear beside them. A list of required fields is not a closed list: the section " +
			"neither permits nor forbids a Server banner or a Date field, and under RFC 7230 the order of " +
			"differently named header fields is not significant. So the RFC does not settle this observable in " +
			"either direction, and no reading of 4.2.2 can be made to settle it.",
		RFCValue: "no-requirement: RFC 6455 4.2.2 fixes the required fields only and does not determine whether " +
			"additional fields may appear, so a three-field and a five-field 101 response both conform",
		JavaRef: "org.java_websocket.drafts.Draft_6455:postProcessHandshakeResponseAsServer",
		JavaObservation: "PINNED SOURCE plus a byte-exact port test against the pinned JAR's own recorded output, " +
			"unchanged by this record and re-read at this landing: postProcessHandshakeResponseAsServer writes " +
			"FIVE fields (Draft_6455.java:434, :435-436, :441, :449, :450), HandshakedataImpl1's TreeMap under " +
			"String.CASE_INSENSITIVE_ORDER sorts them (HandshakedataImpl1.java:50) and Draft.createHandshake writes " +
			"them in that order (Draft.java:275-283), giving Connection, Date, Sec-WebSocket-Accept, Server, " +
			"Upgrade with the literal banner value TooTallNate Java-WebSocket. The port reproduces exactly that, " +
			"pinned by rust/ws-core/tests/handshake_server_response.rs.",
		JavaValue: "five fields in String.CASE_INSENSITIVE_ORDER, including a Server banner naming the Java " +
			"library and a wall-clock Date, and the port emits the same five",
		AutobahnRefs: []string{"autobahn-v25.10.1:1.1.1"},
		// AutobahnResult and AutobahnValue stay EMPTY, as on sequences 57 and
		// 58. Re-running the suite is an owner gate, no run was made for this
		// record, and inheriting an executed marker for a subject no run saw
		// would be the overclaim the whole supersession file exists to refuse.
		Disposition:   "adopt-java",
		MismatchClass: "underspecified-behavior",
		Rationale: "SUPERSEDING ADJUDICATION for ledger sequence 58 (server 101 response fields). WHAT IT " +
			"CORRECTS IS A DISPOSITION, NOT A FACT: every measurement sequence 58 binds is still true, and this " +
			"record restates them rather than revising them. Sequence 58 held `unresolved` on the ground that " +
			"US-011 AC2 forbids the Date field and the Server banner the port emits, and that only the owner could " +
			"say whether AC2 stands or is amended. THE OWNER HAD ALREADY RULED, EIGHT DAYS BEFORE THE FIX LANDED, " +
			"AND CONFIRMED THE READING ON 2026-09-04. FIRST DECISION: " +
			"us010-016-ac-amendment-owner-decision-2026-08-27.json (workspace orchestrator protected store, sha256 " +
			"26849b5ea74006504d18507ac694c00e882e7fd37d4cd8c8502ea824e96ea974) amends every AC clause of " +
			"US-010..US-016 that requires rejecting, transforming or augmenting behaviour the pinned Java-WebSocket " +
			"1.6.0 exhibits, to bind instead to the recorded fidelity authority. US-011 AC2 is in that range and " +
			"its banner clause requires the port to SUPPRESS two fields the pinned Java emits, so it is a clause " +
			"the operative sentence reaches; each carve-out was tested rather than waved past — a vendor banner is " +
			"not a safety-critical bound, not an evidence-machinery clause, and a statement about which bytes go " +
			"on the wire is precisely the behavioural stance the amendment does amend. SECOND DECISION, which needs " +
			"no enumeration to be read: us009-us008-owner-decisions-2026-08-27.json (workspace orchestrator " +
			"protected store, sha256 3a9b24c4b7ee607d981f52e6881ad2476cf03cff01da89bb29461b97f2f99593) key " +
			"us009_normativity, choice JAVA_FAITHFUL_PLUS_SAFE, mirrors shipped observable behaviour EXACTLY and " +
			"carves out only shipped UNSAFETY, enumerated as bounded memory, checked arithmetic and exactly-once " +
			"terminal callbacks; a Server banner and a Date field are none of those, and that stance reaches the " +
			"handshake by name. THE OWNER CONFIRMED ON 2026-09-04 that the amendment's `every AC clause` does " +
			"reach US-011 AC2's banner clause even though that clause is STRICTER than the RFC rather than a " +
			"restatement of it — the single doubt left open when this conflict was filed. DISPOSITION adopt-java: " +
			"the port reproduces shipped Java's five-field response byte-exact against the pinned jar's own output " +
			"and the two decisions above are what license it, so emitting Date and the Server banner is COMPLIANCE " +
			"and not the violation sequence 58 recorded it as. MISMATCH CLASS STAYS underspecified-behavior, AND " +
			"THE REASON IT DOES NOT MOVE WITH THE DISPOSITION IS STATED SO IT IS NOT READ AS AN OVERSIGHT: the " +
			"class says WHERE THE MISMATCH LIVES, not what the port should do. RFC 6455 4.2.2 lists required " +
			"fields and does not determine whether additional fields may appear, so the RFC does not settle this " +
			"observable — true while the disposition was unresolved, still true now that a project-level authority " +
			"has settled what to DO. NO PORT BYTE CHANGES AT THIS LANDING and no US-011 AC2 text is edited: the " +
			"amendment binds that clause without rewriting it. NO AUTOBAHN CLAIM IS MADE: re-running the suite is " +
			"an owner gate and this record's Autobahn preimages are the honest non-execution markers." +
			frozenPrefixOwnerDecision,
	}
}
