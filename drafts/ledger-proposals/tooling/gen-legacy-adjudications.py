"""Emit evidence/java/legacy-record-adjudications.json.

This is a one-shot authoring aid, not a regeneration path: the adjudications
below are JUDGEMENTS, argued from each record's own sealed evidence. The
committed document is the artifact; internal/deltaledger.VerifyLegacyAdjudications
is what binds it to the chain. Run from the repository root.
"""
import json

LEDGER = 'evidence/java/behavior-delta-ledger.json'
SUPERSESSIONS = 'evidence/java/ledger-supersessions.json'
OUT = 'evidence/java/legacy-record-adjudications.json'

JQ = 'java-quirk'
RD = 'rust-defect'
UB = 'underspecified-behavior'

SETTLES = 'evidence-settles-it'
UNSETTLED = 'evidence-does-not-settle-it'

# seq -> (class, argument, blocking_question, contests, draft)
A = {}


def q(seq, cls, argument, blocking='', contests=False, draft=''):
    A[seq] = (cls, ' '.join(argument.split()), ' '.join(blocking.split()), contests, draft)


HS_ACCEPT = (
    "The record's own rfc_value preimage normalizes RFC 6455 section 4.2.1 to "
    "'reject: refuse the opening handshake', so the RFC DETERMINES this observable. "
    "The live pinned Java server accepted: acceptHandshakeAsServer evaluates only "
    "Sec-WebSocket-Version == 13 (Draft_6455.java:262-286) and a non-empty key "
    "(Draft_6455.java:432-441), so the rule the RFC states is never evaluated at all. "
    "Java is on the other side of a determinate requirement, which is java-quirk by "
    "definition. That the port reproduces the acceptance under JAVA_FAITHFUL_PLUS_SAFE "
    "is a DISPOSITION and does not move the class: the mismatch this record binds is "
    "(rfc_expectation, java_observation), and it originates in Java.")

q(1, JQ, "Section 4.1 requires a Host header field and 4.2.1 requires the server to "
         "validate the client handshake. " + HS_ACCEPT)
q(2, JQ, "Section 4.1/4.2.1 require an Upgrade header field containing 'websocket'. " + HS_ACCEPT)
q(3, JQ, "Section 4.2.1 requires the Upgrade value to case-insensitively equal "
         "'websocket'. " + HS_ACCEPT)
q(4, JQ, "Section 4.1/4.2.1 require a Connection header field whose value includes the "
         "'Upgrade' token. " + HS_ACCEPT)
q(5, JQ, "Section 4.2.1 requires the Connection value to include the 'Upgrade' token. " + HS_ACCEPT)

KEY = (
    "Section 4.2.1 item 5 is determinate: Sec-WebSocket-Key must be base64 that decodes "
    "to exactly 16 bytes, and the record's rfc_value normalizes it to 'reject'. "
    "generateFinalKey (Draft_6455.java:832-841) SHA-1 hashes any non-empty header string "
    "after String.trim, so neither the encoding nor the decoded length is ever examined "
    "and the accept value is derived from the malformed key. Java is on the other side of "
    "a determinate rule: java-quirk. The port's reproduction of it is a disposition, not "
    "a class, and this record's Autobahn refs are nominal anchors, so no Autobahn "
    "observation bears on the attribution either way.")

q(6, JQ, "First recorded non-base64 key shape. " + KEY)
q(7, JQ, "Second recorded non-base64 key shape, distinct wire bytes from us005.hs.0019, "
         "same predicate. " + KEY)
q(8, JQ, "First recorded wrong-decoded-length key shape. " + KEY)
q(9, JQ, "Second recorded wrong-decoded-length key shape, distinct wire bytes from "
         "us005.hs.0021, same predicate. " + KEY)

q(10, JQ,
  "The record's rfc_expectation cites RFC 9110 section 5.3, which forbids consuming a "
  "duplicated singleton field such as Sec-WebSocket-Key as one combined value, and its "
  "rfc_value normalizes that to 'reject'. translateHandshakeHttp joins duplicated values "
  "with the literal '; ' (Draft.java:119-125) and accepts, computing the accept value over "
  "the joined string. Java is on the other side of a determinate rule: java-quirk. THIS IS "
  "THE WEAKEST OF THE JAVA-QUIRK CALLS AND IS MEANT TO BE ARGUED WITH: section 5.3's "
  "separator sentence is written for list-based fields, and a reader who holds that the RFC "
  "leaves a recipient's handling of a duplicated NON-list field open would class this "
  "underspecified-behavior. I follow the record's own sealed normalization rather than "
  "overriding it, which is the same deference sequence 41 gets.")

TOKEN = (
    "The record's rfc_expectation cites RFC 9112 section 5, where field-name = token, so a "
    "name containing a non-token character makes the message invalid; the rfc_value "
    "normalizes that to 'reject'. Java performs no header-name validation at all: "
    "translateHandshakeHttp stores whatever precedes the first colon (Draft.java:115-125), "
    "and the only parse-level rejection in the whole path is a line with no colon. Java is "
    "on the other side of a determinate rule, so the mismatch originates in Java.")

q(11, JQ, "First recorded non-token header-name shape. " + TOKEN)
q(12, JQ, "Second recorded non-token header-name shape, distinct wire bytes from "
          "us005.hs.0029. " + TOKEN)

q(13, UB,
  "CONTESTED BY LATER EVIDENCE, AND THE CONTEST DECIDES THE CLASS. This record's sealed "
  "rfc_expectation says RFC 9112 section 2.2 'forbids a bare LF as a line terminator, so "
  "the message is malformed and must be refused'. Sequence 39, appended later and about the "
  "same clause on the client direction, states the opposite after reading it: section 2.2 "
  "'expressly PERMITS recognizing one' -- 'a recipient MAY recognize a single LF as a line "
  "terminator' -- so declining the MAY, as Draft.readLine does by terminating only on CRLF "
  "(Draft.java:78), is conformant. On the later and correct reading the RFC does not "
  "determine this observable, which makes the mismatch underspecified-behavior and not the "
  "java-quirk the record's own basis implies. This is the same defect sequences 45-47 "
  "corrected for the section 10.4 basis, at a clause nobody re-checked; it is unsuperseded, "
  "so this entry carries the obligation of a draft.",
  contests=True, draft='drafts/ledger-proposals/legacy-13-bare-lf-server-basis-correction.json')

BUDGET_SUPERSEDED = (
    "The RFC basis this record bound was WRONG and the chain already says so. Sequence {sup} "
    "supersedes it (evidence/java/ledger-supersessions.json) with the finding that section "
    "10.4 is scoped to FRAMES and to total message size after reassembly, that the opening "
    "handshake is neither, and that 'no clause of RFC 6455 mandates a handshake size, "
    "header-count or header-line limit'. On the corrected basis the RFC does not determine "
    "this observable at all: shipped Java is unbounded (translateHandshakeHttp reads "
    "unboundedly, Draft.java:70-132) and the port budgets, so Java and the port each chose "
    "differently on a point the RFC leaves open. That is underspecified-behavior. The class "
    "is taken from the CORRECTED basis rather than from this record's own preimage. THIS ENTRY "
    "CONTESTS THE RECORD IT ADJUDICATES, and discharges that obligation by naming the "
    "superseding SEQUENCE rather than a draft: the correction is already appended, so drafting "
    "one would be proposing a record the chain has. The gate re-derives the link from the "
    "records' own hashed rationales, so superseded_by_sequence={sup} is checked against sealed "
    "content and not taken on this entry's word.")

q(14, UB, BUDGET_SUPERSEDED.format(sup=45))
q(15, UB, BUDGET_SUPERSEDED.format(sup=46))
q(16, UB, BUDGET_SUPERSEDED.format(sup=47))

q(17, JQ,
  "Section 5.2 is determinate: the payload length must use the minimal number of bytes, and "
  "the rfc_value normalizes it to 'reject: fail the WebSocket connection with 1002 on a "
  "non-minimal extended payload length'. translateSingleFrame performs no minimality check "
  "(mirrored at derive.go:399-420) and processes both the 16-bit and the 64-bit non-minimal "
  "forms normally. Java is on the other side of a determinate rule, so the mismatch "
  "originates in Java, whatever the port then chooses to do with it.")

q(18, JQ,
  "Section 5.1 is determinate about mask-by-role -- client-to-server frames masked, "
  "server-to-client unmasked, fail with 1002 otherwise -- and the rfc_value normalizes it "
  "to 'reject'. The pinned runtime unmasks when the mask bit is set and otherwise reads the "
  "payload directly, with no role check at all (derive.go:439-447). Java is on the other "
  "side of a determinate rule: java-quirk. Noted for the reader: this record's Java side "
  "rests on the quarantined-source read plus the US-005 calibration, because the corpus "
  "scopes itself to spec-conformant masking, so the shape is corpus-invisible. That "
  "weakens the OBSERVATION's provenance, not the attribution: the source reading and the "
  "RFC both point the same way.")

q(19, None,
  "THE EVIDENCE DOES NOT SETTLE THIS ONE, AND SAYING SO IS THE ANSWER. Section 5.2 is "
  "determinate (the most significant bit of a 64-bit extended length must be 0, fail 1002), "
  "so the class turns entirely on which side Java is on -- and this record's own java_value "
  "preimage says Java's side is 'undefined-in-evidence: negative signed-long length with "
  "untested downstream behavior (outside the verified space)'. Two classes are live and the "
  "record chooses between neither: java-quirk if the pinned runtime's negative-long parse "
  "produces some non-1002 observable, and rust-defect if it in fact fails the connection, "
  "since the port deliberately parses UNSIGNED and rejects 1009 at length site 10 rather "
  "than 1002. I examined the record, the definition preimages and the seed "
  "(rust/ws-core/fuzz-seeds/us012/high-bit-64.hex); nothing in the committed evidence "
  "records a Java observable here.",
  blocking="Execute the high-bit-64 seed against the pinned Java-WebSocket 1.6.0 jar (sha256 "
           "eae29213...) through the same oracle path the rest of this ledger's Java "
           "observations use, and record what the negative-long length actually produces: a "
           "1002 close, some other typed rejection, or a hang. OWNER ACTION -- it needs a "
           "live Java execution, which no gate on this branch may trigger.")

q(20, UB,
  "The verdicts AGREE: this record's own opening sentence says 'both the RFC expectation and "
  "pinned Java reject RSV-bit and non-final control frames with 1002'. The only difference is "
  "the observable rejection SITE -- Java consumes the full frame first. RFC 6455 does not fix "
  "a detection site, and the chain says so itself one record later: sequence 21's sealed "
  "rfc_value reads 'reject: fail with 1002 on an over-125 control payload length (the RFC "
  "states no detection site)'. So the RFC does not determine the disputed observable, and "
  "Java and an RFC-minimal parser differ on a point it leaves open: underspecified-behavior. "
  "Recorded as a reading, not a refutation: this record's own rfc_expectation says 'an "
  "RFC-strict endpoint detects both at the frame header', which describes what a strict "
  "endpoint would do rather than what the RFC requires.")

q(21, UB,
  "The record settles its own class. The verdicts agree (1002) and its sealed rfc_value says "
  "in as many words that 'the RFC states no detection site', so the disputed observable -- "
  "rejecting the control extended-length MARKER at header byte 2 without reading the declared "
  "length -- is one RFC 6455 does not determine. Java chose byte 2; an RFC-minimal parser "
  "reads the length first; the consumed-byte observable differs. That is "
  "underspecified-behavior exactly as the vocabulary defines it, and internal/deltaledger's "
  "RFC-determinacy rule is not even reached, because the leading token is 'reject'.")

q(22, UB,
  "The record's opening sentence is the argument: 'the reject verdicts match the RFC, but the "
  "pinned runtime's consumed-byte offsets and its discard-the-chunk translate semantics are "
  "Java-specific observables an RFC-minimal parser would not produce'. Section 5.2 defines the "
  "frame grammar and the verdict; it says nothing about how many bytes a receiver has consumed "
  "when it fails, and nothing about whether frames already decoded from the same transport "
  "chunk survive a later frame's rejection. Both are choices the RFC leaves open and on which "
  "Java and an RFC-minimal parser differ: underspecified-behavior.")

q(23, UB,
  "Both sides reach the same RFC-mandated verdict. Section 8.1 requires failing with 1007 on "
  "invalid UTF-8 and pinned Java does fail with 1007; even the record's own strict reading "
  "acts 'when the message completes'. What differs is an intermediate observable -- Java's "
  "translate-time Hoehrmann DFA accepts a dangling incomplete tail and RECORDS the frame "
  "before the strict process-time gate rejects the assembled message. RFC 6455 does not "
  "specify whether a receiver may emit a per-frame record before completing message-level "
  "validation, so the two-stage timing is a choice on a point it leaves open: "
  "underspecified-behavior, not a departure from a determinate rule.")

q(24, UB,
  "Section 10.4 is genuinely in scope here -- unlike sequences 45-47, this record is about "
  "frames and reassembled messages, which is exactly what 10.4 addresses -- and it still does "
  "not determine the observable. It expects implementations to have limits; it fixes neither "
  "the SITE at which the accumulated size is checked nor the vocabulary in which an overflow "
  "is reported. Java checks only at message starts and fins (checkBufferLimit, quirk Q23) and "
  "splits the overflow observable by fragment position (1009 at a fin, "
  "BUFFER_LIMIT_EXCEEDED with no close code on a non-fin continuation); an every-fragment "
  "checker would report differently. Two conforming choices on an open point: "
  "underspecified-behavior.")

q(25, JQ,
  "Section 5.5.2 is a MUST -- an endpoint receiving a Ping MUST send a Pong with identical "
  "application data unless it already sent a Close -- and the rfc_value normalizes it to "
  "'auto-respond'. The pinned runtime's oracle-observable behaviour produces a ping event and "
  "NO pong write (quirk Q18; derive.go:671-674), live-executed on corpus families "
  "us005.pub.0002 and us005.pub.0071 with no pong write recorded. Java is on the other side of "
  "a determinate MUST: java-quirk. STATED LIMIT OF THIS ATTRIBUTION: the observation is scoped "
  "to the Draft-level oracle entry point the corpus measures, and the record says so ('no pong "
  "write is ever produced by the core'). Nothing in this ledger records whether the shipped "
  "full stack pongs; if it does, this is the same entry-point split sequences 44, 48 and 49 "
  "carry, and the class would still be java-quirk at the measured point.")

q(26, JQ,
  "Section 5.5 is determinate: all control frames MUST have a payload length of 125 bytes or "
  "less, and the rfc_value normalizes it to 'refuse-send'. The pinned runtime's send path "
  "performs no check at all (quirk Q17; Execution.sendControl mirrors "
  "WebSocketImpl.sendFrame), so an oversized local ping or pong is encoded with an extended "
  "length and written to the wire. Java is on the other side of a determinate rule: "
  "java-quirk. The deliberate asymmetry the record names -- inbound over-125 control frames "
  "are still rejected 1002 -- is a property of the port's reproduction, not of the class.")

q(27, JQ,
  "Section 5.5.1 is determinate: a close payload is either empty or begins with a 2-byte "
  "status code, so a 1-byte payload is malformed and the rfc_value normalizes it to 'reject: "
  "treat the 1-byte close payload as a protocol failure'. CloseFrame.setPayload instead maps "
  "the single byte to code 1002 with an empty reason and the frame proceeds as a VALID close "
  "through an ordinary close handshake (quirk Q11, live-oracle-confirmed on us005.pub.0035). "
  "Java is on the other side of a determinate rule: java-quirk.")

q(28, JQ,
  "Section 5.5.1 determines this observable through a SHOULD -- an endpoint answering a Close "
  "echoes the status code it received -- and the rfc_value normalizes it to "
  "'echo-received-code'. I treat a SHOULD as determinate for classification: RFC 2119 allows "
  "ignoring one only with the full implications understood, and no such reason is recorded "
  "here. The pinned runtime's echoed frame object always carries the CloseFrame constructor "
  "payload [0x03,0xe8] regardless of the received code (quirks Q10/Q19), and the inbound "
  "frame RECORD carries it too. Java is on the other side: java-quirk. Distinguish sequence "
  "33, which is the WIRE composition of the same ingredients and comes out rust-defect, "
  "because there the shipped full stack agrees with the RFC and the port did not.")

q(29, UB,
  "Section 7.1.4 defines the closed state and 7.1.5 the connection close code; neither "
  "mandates that a receiver expose DISTINCT application-visible failure classes for EOF "
  "before, during and after a close handshake. The record's own rfc_expectation says only "
  "that 'an RFC-strict endpoint reports these as distinct failure classes', which is an "
  "inference about a strict design rather than a clause. The pinned runtime collapses every "
  "EOF into one close vocabulary (quirk Q20, WebSocketImpl.eot) and a strict design would "
  "not: two choices on a point the RFC leaves open, so underspecified-behavior. The record's "
  "own residual honest gap -- EOF before the handshake completes is an Unimplemented refusal "
  "-- is outside this record and does not change the class.")

q(30, JQ,
  "Sections 7.4.1 and 7.4.2 determine the close-code table: which values are legal on the "
  "wire, which are reserved and never sent, and 1002 as the protocol-error code. The pinned "
  "runtime's CloseFrame.isValid chain (quirk Q13; CloseFrame.java:226-243) disagrees with "
  "that table in two ways at once, as the record's own opening sentence says: in membership "
  "granularity, banning the whole 1016-2999 band the RFC reserves for future definition "
  "rather than for rejection, and in the REPORTED code, answering the 1007-with-empty-reason "
  "case AS 1007 where the table makes it a protocol error. Java is on the other side of a "
  "determinate registry: java-quirk.")

q(31, UB,
  "The RFC-governed observable is satisfied by both sides, and this record's own safety note "
  "says so: section 7.4.1's rule is that 1015 MUST NOT be SENT in a Close frame, and 'no "
  "reserved code reaches the wire (the isValid chain still rejects 1005/1015), so the RFC's "
  "on-the-wire prohibition is never violated'. What differs is how a LOCAL send_close(1015) "
  "request is reported back to its caller: Java's CloseFrame.setCode silently rewrites 1015 "
  "to 1005 before validation and the refusal surfaces as the 1005 case, where an RFC-shaped "
  "API would name the 1015 violation. RFC 6455 says nothing about local API error reporting, "
  "so this is a choice on a point it does not reach: underspecified-behavior.")

q(32, JQ,
  "Sections 5.5.1 and 8.1 are determinate: the close reason after the 2-byte code must be "
  "valid UTF-8 and a receiver that gets an invalid one fails the connection with 1007, which "
  "the rfc_value normalizes to 'reject: 1007 close on an invalid-UTF-8 close reason'. In the "
  "pinned runtime the reason decodes to null and the isValid dereference raises a "
  "NullPointerException-class rejection with NO close code at all (quirk Q12, oracle failure "
  "code JAVA_RUNTIME_REJECTION at translate time). Java is on the other side of a determinate "
  "rule, and 'no close code' is as far from 1007 as an observable gets: java-quirk.")

q(33, RD,
  "THIS ONE IS A RUST DEFECT, AND THE DISCRIMINATOR IS WHICH SIDE JAVA IS ON. Section 5.5.1's "
  "SHOULD-echo and section 7.4.1's 1002 both point at a 1002 reply to a malformed 1-byte "
  "close, and the SHIPPED FULL STACK agrees with them: Draft_6455.processFrame routes CLOSING "
  "to processFrameClosing, which reads the DECODED cf.getCloseCode() and calls "
  "webSocketImpl.close(code, reason, true), so WebSocketImpl builds its own frame carrying the "
  "received code. RFC and Java agree; the port's core-level Q19/Q10 composition replied 1000, "
  "which wstest scores WRONG CODE. A port short of a target Java and the RFC share is "
  "rust-defect by definition. It is REMEDIED, in ws-driver's CloseEchoPolicy, with ws_core "
  "byte-identical -- so the class records where the mismatch came from, not whether it is "
  "still open.")

q(34, UB,
  "The record's sealed rfc_value is 'unordered: the RFC permits either the echo-then-fail or "
  "the fail-immediately observable', which settles the class before any argument: section 5.4 "
  "requires a completed fragmented message to be delivered and section 7.1.7 permits failing "
  "immediately on a violation, and the RFC does not fix which wins when one read carries both. "
  "Java's two-phase decode enqueues the echo during dispatch and the failure path's "
  "flushAndClose flushes it; the port's typed failure lands before delivery. Two conforming "
  "choices on an open point, which Autobahn itself scores as OK versus NON-STRICT rather than "
  "pass versus fail: underspecified-behavior.")

q(35, JQ,
  "The RFC determines this observable and the record's rfc_value normalizes it to 'stay-open': "
  "section 7.1.3 makes CLOSING the state an endpoint occupies once it has SENT a Close frame, "
  "and an endpoint whose local close request is refused before any frame reaches the wire has "
  "sent none. Shipped WebSocketImpl.close reaches CLOSING anyway, through an unconditional "
  "tail assignment at WebSocketImpl.java:503 on the caught-InvalidDataException path. That is "
  "Java on the other side of a determinate rule: java-quirk. THE PORT IS ON THE RFC'S SIDE "
  "HERE, and not by preference: the change to match the source was implemented, measured, and "
  "reverted when the public corpus failed 1 of 74 because live Java's own recording of "
  "us005.pub.0000 is final_state open. The class names where the mismatch originates; the "
  "measured refutation is why the port does not reproduce it.")

CLIENT_BUDGET = (
    "The record's sealed rfc_value is 'no-requirement: the RFC prescribes no handshake "
    "head-size, header-count or header-line bound, so both an unbounded parser and a budgeted "
    "one conform'. That is decisive and mechanical: internal/deltaledger's determinacy rule "
    "refuses java-quirk on any record whose rfc_value opens with that token, because a class "
    "asserting the RFC determines the observable cannot stand where the record's own preimage "
    "says it does not. Shipped Java is unbounded ({site}); the port keeps a configured budget "
    "and refuses with ClientHandshakeOutcome::LimitExceeded. Java and the port each chose "
    "differently on a point the RFC leaves open: underspecified-behavior. The direction is the "
    "unusual one -- the port is STRICTER -- which the record itself flags as a SAFE "
    "STRENGTHENING; direction bears on the disposition, not on the class.")

q(36, UB, CLIENT_BUDGET.format(site="WebSocketImpl.java:370-387 grows tmpHandshakeBytes "
                                   "without a ceiling"))
q(37, UB, CLIENT_BUDGET.format(site="the header loop in translateHandshakeHttp, "
                                   "Draft.java:113-127, has no count bound"))
q(38, UB, CLIENT_BUDGET.format(site="readLine accumulates to the CRLF pair with no per-line "
                                   "ceiling, Draft.java:70-87"))

q(39, UB,
  "The record's sealed rfc_value is 'recipient-choice: RFC 9112 section 2.2 permits but does "
  "not require recognizing a bare LF as a line terminator, so accepting the response and never "
  "completing it are both conformant', and it says explicitly that an earlier draft claiming "
  "section 2.2 'forbids' a bare LF was wrong. The RFC therefore does not determine the "
  "observable; shipped Java declines the MAY (Draft.readLine returns only on the CR-LF pair, "
  "Draft.java:78) and stalls as an incomplete head, and the corpus's RFC-derived MODEL rejects. "
  "Model versus Java on a point the RFC leaves to the recipient: underspecified-behavior. This "
  "record is the reason sequence 13, which binds the OPPOSITE reading of the same clause on "
  "the server direction, is filed as contested.")

q(40, JQ,
  "The record's rfc_value is 'reject: refuse the server's opening handshake', resting on RFC "
  "9110 section 5.1's field-name = token, which a name containing a space is not. Java performs "
  "no header-name validation on either direction: translateHandshakeHttp splits on the FIRST "
  "colon and stores whatever precedes it (Draft.java:113-127). The record's own seed makes the "
  "mechanism visible -- 'Up grade' is stored as a field named 'Up grade', so the lookup for "
  "'Upgrade' finds nothing and basicAccept rejects NOT_MATCHED, the right outcome for the wrong "
  "reason, while a non-token name on any header the client never consults is accepted outright. "
  "Java is on the other side of a determinate rule: java-quirk.")

q(41, JQ,
  "The record's rfc_value is 'malformed-message-or-comma-combine', and its own corrected text "
  "is precise about what section 5.3 does and does not say: it places the MUST NOT on the "
  "SENDER, it permits a recipient to combine duplicates, and where a recipient combines them it "
  "fixes the separator -- 'separated by a comma (\",\") and optional whitespace'. Java joins "
  "with the literal '; ' (Draft.java:119-125), a separator the RFC does not specify, and judges "
  "the joined value. On the separator the RFC is determinate and Java is on the other side: "
  "java-quirk. LIKE SEQUENCE 10, THIS IS CONTESTABLE and I record it as a reading: a reviewer "
  "who holds section 5.3's comma clause to be descriptive of list-based fields only would class "
  "it underspecified-behavior. The two records get the same answer for the same reason, which is "
  "the point of stating the rule once.")

q(42, JQ,
  "RFC 9112 section 6.3 is quoted verbatim in the record's own rfc_expectation and is a MUST: "
  "where a request's Transfer-Encoding does not end in chunked the server MUST respond 400 and "
  "close, and the rfc_value normalizes that to 'reject'. Shipped Java has no transfer-coding "
  "handling of any kind -- the record establishes the absence by search rather than assumption, "
  "noting the string 'Transfer-Encoding' does not occur anywhere in src/main/java -- so the "
  "field is parsed into the map and never read. Java is on the other side of a determinate MUST: "
  "java-quirk. The record's request-smuggling note is a deployment-topology risk that follows "
  "from the quirk; it does not change where the mismatch originates.")

q(43, UB,
  "The record's sealed rfc_value is 'unspecified: the RFC neither requires nor forbids the "
  "connection remaining usable after a pre-handshake send is refused', so the determinacy rule "
  "forbids java-quirk here and the RFC-silence arm is the one that applies. Shipped Java's "
  "refusal is RECOVERABLE -- the WebsocketNotConnectedException throw at WebSocketImpl.java:667 "
  "mutates nothing and the instance stays usable -- while the port refuses with "
  "FailureCode::StateViolation and POISONS the core under its uniform partial-execution "
  "discipline. Java and the port each chose differently on a point outside the protocol "
  "entirely: underspecified-behavior. The record notes the arm is corpus-invisible, so no "
  "live-oracle observation bears on it either way.")

q(44, JQ,
  "The RFC determines this one and the record's rfc_value normalizes it to 'closed': section 5.2 "
  "requires an endpoint receiving a nonzero RSV bit with no negotiated extension to Fail the "
  "WebSocket Connection, and 7.1.7 makes failing it take the endpoint out of OPEN. The MEASURED "
  "pinned runtime does not: the live recording for us005.pub.0005 keeps final_state open. Java "
  "at the observation point this ledger measures is on the other side of a determinate rule: "
  "java-quirk. TWO THINGS THE READER SHOULD WEIGH AGAINST THIS. The record's java_value is "
  "'entry-point-dependent' -- WebSocketImpl.decodeFrames DOES close on the caught exception, so "
  "a full-stack reading would put Java on the RFC's side and the port alone in the open, which "
  "is the shape that makes sequences 33 and 49 rust-defect. And the Codex plane at df6aa20 "
  "ranks the RFC above Java at this exact pointer while classing Java's open as java_quirk, "
  "which agrees with this attribution even where it disagrees about what to do.")

SERVER_BUDGET_CORRECTED = (
    "This is the CORRECTING record, and its own corrected basis settles the class. Its sealed "
    "rfc_value is 'no-requirement: the RFC prescribes no handshake head-size, header-count or "
    "header-line bound', reached by quoting section 10.4 verbatim and finding it scoped to "
    "frames and to total message size after reassembly rather than to the opening handshake. "
    "internal/deltaledger's determinacy rule therefore refuses java-quirk on it mechanically. "
    "Shipped Java is unbounded ({site}); the port keeps the configured budget deliberately under "
    "the AC-amendment's rule that checked config limits are not relaxed. Two conforming choices "
    "on a point the RFC leaves open: underspecified-behavior. The superseded record at sequence "
    "{sub} carries the same class for the same reason.")

q(45, UB, SERVER_BUDGET_CORRECTED.format(
    site="translateHandshakeHttp reads unboundedly, Draft.java:70-132, and "
         "WebSocketImpl.java:370-387 grows tmpHandshakeBytes without bound", sub=14))
q(46, UB, SERVER_BUDGET_CORRECTED.format(
    site="the header loop in translateHandshakeHttp is unbounded, Draft.java:113-127", sub=15))
q(47, UB, SERVER_BUDGET_CORRECTED.format(
    site="readLine returns only on the CRLF pair with no per-line ceiling, Draft.java:70-87",
    sub=16))

q(48, JQ,
  "The class record for the same proposition sequence 44 carries on one instance, and it gets "
  "the same answer for the same reason. Section 7.1.7's Fail the WebSocket Connection is "
  "determinate and the rfc_value normalizes it to 'closed: every inbound protocol-level decode "
  "rejection takes the endpoint out of OPEN'. On all eighteen public-corpus scenarios the "
  "measured runtime records JAVA_INVALID_DATA raised on a bytes step with final_state "
  "nevertheless open. Java at the measured entry point is on the other side of a determinate "
  "rule: java-quirk. The record's own framing is the caution to carry forward -- shipped "
  "WebSocketImpl.decodeFrames DOES close on these rejections and the adapter path never reaches "
  "it, so both readings are faithful to different entry points of one jar, and this attribution "
  "is made at the entry point the corpus measures.")

q(49, RD,
  "RUST DEFECT, and the same discriminator as sequence 33: at the observation point where this "
  "divergence was externally visible, the RFC and shipped Java AGREE and the port was short of "
  "both. Section 7.1.7 requires a Close frame with an appropriate status code before the "
  "connection goes away and the rfc_value normalizes it to 'send-1002-then-close'; "
  "WebSocketImpl.decodeFrames answers exactly that (WebSocketImpl.java:405-408). Our stack "
  "answered with nothing and dropped TCP. The owner ruled c6-match-java-fully, which names Java "
  "as the target -- the definition's own second arm for rust-defect. It is REMEDIED at one "
  "layer, in ws-testee's io_loop, with ws_core deliberately unchanged at the Draft-level entry "
  "point the differential corpus measures; the class records where the mismatch came from, and "
  "the retained half is a disposition question this entry does not touch.")


def main():
    d = json.load(open(LEDGER))
    recs = {r['sequence']: r for r in d['records']}
    rats = {s: r['delta']['rationale'] for s, r in recs.items()}
    # A record the chain itself withdraws is contested by definition, and the
    # correction is already appended, so the entry names the SEQUENCE rather
    # than a draft. This is read here from the sidecar because this is an
    # authoring aid; the gate re-derives the same links from the records' own
    # hashed rationales and refuses a value the chain does not say.
    superseded_by = {
        link['superseded_sequence']: link['superseding_sequence']
        for link in json.load(open(SUPERSESSIONS))['links']
    }

    def first_sentence(text, minlen=60):
        i = minlen
        while True:
            j = text.find('. ', i)
            if j < 0:
                return text[:max(minlen, 80)]
            cand = text[:j + 1]
            if len(cand) >= minlen:
                return cand
            i = j + 2

    entries = []
    for seq in range(1, 50):
        rec = recs[seq]
        cls, argument, blocking, contests, draft = A[seq]
        quote = first_sentence(rats[seq])
        # uniqueness assertion at authoring time; the gate re-checks it.
        assert quote in rats[seq], seq
        for s, r in rats.items():
            assert s == seq or quote not in r, (seq, s)
        assert len(argument) >= 160, (seq, len(argument))
        if cls is None:
            exam = UNSETTLED
            assert len(blocking) >= 60, (seq, len(blocking))
        else:
            exam = SETTLES
            assert blocking == '', seq
        withdrawn = superseded_by.get(seq, 0)
        entry = {
            'sequence': seq,
            'delta_id': rec['delta']['delta_id'],
            'record_digest': rec['record_digest'],
            'subject_ref': rec['delta']['subject_ref'],
            'examination': exam,
            'mismatch_class': cls or '',
            'cited_rfc_refs': list(rec['delta']['rfc_refs']),
            'cited_java_ref': rec['delta']['java_ref'],
            'rationale_quote': quote,
            'argument': argument,
            'blocking_question': blocking,
            'contests_record_basis': contests or bool(withdrawn),
            'supersession_draft': draft,
        }
        if withdrawn:
            entry['superseded_by_sequence'] = withdrawn
            # The class a withdrawn record is filed under must equal the class
            # its replacement is filed under: they are two statements about one
            # observable, and the later one carries the corrected basis.
            assert A[withdrawn][0] == cls, (seq, withdrawn, cls, A[withdrawn][0])
        entries.append(entry)

    classed = 0
    for r in d['records']:
        if r['delta'].get('mismatch_class'):
            classed += 1
        elif r['sequence'] <= 49 and A[r['sequence']][0]:
            classed += 1
    residual = len(d['records']) - classed

    doc = {
        '$schema': '../../schemas/legacy-record-adjudications-1.0.0.schema.json',
        'schema_version': '1.0.0',
        'evidence_kind': 'legacy-record-adjudications',
        'accepted_root_digest': d['accepted_root_digest'],
        'ledger_document': 'evidence/java/behavior-delta-ledger.json',
        'pre_vocabulary_sequence': 49,
        'pre_vocabulary_head': recs[49]['record_digest'],
        'records_without_ac3_class': residual,
        'adjudications': entries,
    }
    with open(OUT, 'w') as f:
        json.dump(doc, f, indent=2)
        f.write('\n')

    counts = {}
    for seq in range(1, 50):
        counts[A[seq][0] or 'UNRESOLVED'] = counts.get(A[seq][0] or 'UNRESOLVED', 0) + 1
    print('wrote', OUT)
    print('counts over the 49:', counts)
    print('records_without_ac3_class =', residual, 'of', len(d['records']))


main()
