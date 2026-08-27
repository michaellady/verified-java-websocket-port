\* US-016 abstract close, EOF, and terminal-state model (AC4) for the
\* verified Java-WebSocket port (Claude plane). This model abstracts the
\* SHIPPED PORT lifecycle -- ws_core::connection::Connection
\* (rust/ws-core/src/connection.rs: send_close, process_close_frame,
\* handle_eof, handle_pre_open_command) together with the pure close
\* vocabulary ws_core::close (normalize_send_close_code,
\* close_code_rejection) -- which is Java-faithful, not RFC-idealized. The
\* behavioral authority is the pinned quarantined Java-WebSocket 1.6.0 tree
\* at .quarantine/Java-WebSocket-da3cf2a777aed862f2f5b5cf060cae7969958667/
\* src/main/java/org/java_websocket/ (all \* JAVA: citations below are
\* package-root-relative file:line references into that tree) as projected
\* by the reference model internal/corpora/derive.go, which the US-016
\* owner amendment names as the binding fidelity authority.
\*
\* STAGE AS: CloseModel.tla -- TLA+ module identifiers cannot contain a
\* hyphen, so a TLC run must stage this file as CloseModel.tla and
\* close-model.cfg as CloseModel.cfg in a scratch directory:
\*   cp close-model.tla CloseModel.tla
\*   cp close-model.cfg CloseModel.cfg
\*   java -cp tla2tools.jar tlc2.TLC -config CloseModel.cfg CloseModel
\*
\* MODEL_CHECK: EXECUTED -- see assurance/formal/close-model-results.json
\* for the executed record (attempt id, tool digest, banners, exit codes,
\* state counts, receipt digests). The results document is the authority;
\* this header is a pointer, not a second copy of the numbers.
\*
\* CLAIM CEILING: proved-model only, exactly as the US-006 connection model
\* and US-012 AC4's "the abstract temporal model remains separately labeled
\* proved-model if executed". Checking this abstraction establishes NOTHING
\* about the production Rust connection core without a reviewed
\* composition/refinement link. No proof-only duplicate implementation
\* exists or is permitted: this file is specification language only.
\*
\* RELATIONSHIP TO THE US-006 CONNECTION MODEL. assurance/formal/
\* connection-model.tla models the SHIPPED JAVA connection lifecycle
\* (including Java's unbounded outQueue, its truncated-tail two-stage text
\* rejection, and its at-least-once terminal delivery under listener
\* re-entry). This model instead abstracts the PORT's Sans-I/O kernel: the
\* kernel has no listener callbacks and no I/O, so its terminal discipline
\* is the entry into the absorbing Closed state plus the fatal-poison flag,
\* not a callback count. The two models therefore check different objects
\* and neither subsumes the other; where they overlap (the CloseFrame
\* normalization table) the tables are stated independently in both, so a
\* mis-normalization in either is caught.
\*
\* JAVA-FAITHFUL, NOT RFC-STRICT. Each divergence below is recorded in
\* evidence/java/behavior-delta-ledger.json and is modeled here as the
\* port's actual behavior, never as the RFC's:
\*   ledger sequence 27, delta-d509ac380f5158... (one-byte-close-payload):
\*     the RFC treats a one-byte close payload as malformed; the pinned
\*     runtime converts it into a VALID close with code 1002 and completes
\*     the close handshake. Modeled by the "one_byte" inbound class mapping
\*     to an ACCEPT with code 1002, not to a rejection.
\*   ledger sequence 28, delta-954132f2fb7819... (constructor-payload-echo):
\*     the RFC-shaped echo reflects the received status code; the pinned
\*     runtime echoes the CONSTRUCTOR payload [0x03, 0xe8] (= 1000) while
\*     open. Modeled by the echo action's payload class "constructor" and
\*     pinned by the EchoCarriesConstructorPayload invariant, which is
\*     falsified the moment an echo mirrors the received code.
\*   ledger sequence 29, delta-e6f5b06cb674e6... (eof-ordinary-close): the
\*     RFC-strict design distinguishes EOF failure classes; the pinned
\*     runtime collapses every EOF into the ordinary close vocabulary with
\*     the governing detail. Modeled by the three declared EOF arms.
\*   ledger sequence 30, delta-4b0ac360177411... (isvalid-rejection-chain):
\*     the RFC registry classes and Java's isValid chain disagree in both
\*     membership granularity and the REPORTED code. Modeled by
\*     CloseCodeRejection, which is Java's literal chain order.
\*   ledger sequence 31, delta-03e9d066f84aeb... (setcode-1015-
\*     normalization): the pinned runtime silently rewrites 1015 to 1005
\*     before validation. Modeled by NormalizeSendCode.
\*   ledger sequence 32, delta-bfeedfec04c8e1... (invalid-utf8-reason-
\*     runtime-rejection): the RFC fails with 1007; the pinned runtime
\*     surfaces a NullPointerException-class rejection with NO close code.
\*     Modeled by the "invalid_utf8_reason" inbound class producing a
\*     runtime_rejection whose reported code is 0 (absent).
\*
\* TWO REAL FINDINGS RECORDED, NOT SUPPRESSED.
\*   FINDING 1 (Q14 normalization is observationally inert on the send
\*   path). The port's normalize_send_close_code rewrites 1015 to 1005 but,
\*   unlike Java's CloseFrame.setCode (framing/CloseFrame.java:179-187),
\*   does NOT also clear the reason (:184). The difference is inert: 1005
\*   with a non-empty reason is rejected 1002 by the second chain arm and
\*   1005 with an empty reason is rejected 1002 by the fourth, and an
\*   un-normalized 1015 is rejected 1002 by the fourth as well -- every
\*   route reports 1002 and emits no frame. The invariant
\*   TlsErrorSendAlwaysRejectedAs1002 checks that mechanically over both
\*   reason kinds, so the inertness is a checked fact rather than an
\*   argument. Nothing is "fixed": the port's observable behavior matches
\*   the fidelity authority.
\*   FINDING 2 (the send-path rejection does not transition, by design).
\*   Shipped Java's close(code, message, remote) catches the
\*   InvalidDataException raised by closeFrame.isValid and then calls
\*   flushAndClose(ABNORMAL_CLOSE, ...) followed by readyState = CLOSING
\*   (WebSocketImpl.java:488-503), so the Java endpoint ENTERS CLOSING on an
\*   illegal local close code. The port's Sans-I/O kernel instead returns
\*   the typed failure to the caller, emits no frame, and does not
\*   transition -- exactly as the reference model's sendClose does
\*   (internal/corpora/derive.go). That reference model is the binding
\*   fidelity authority under the US-016 owner amendment, so the model
\*   follows the port; the Java-side difference is stated here rather than
\*   hidden, and it lives in the adapter layer's scope (US-018), not the
\*   kernel's.
\*
\* MODEL SCOPE. The model covers the US-016 obligations that are lifecycle
\* facts: the local close path with its normalization and validity chain,
\* the inbound close path with the shipped payload normalization and the
\* echo-while-open rule, the three EOF arms, the state gates that refuse
\* data after closing and everything after closed, the absorbing terminal
\* state, and the absorbing fatal-poison flag. DELIBERATELY OUT OF SCOPE,
\* each owned by another artifact: frame-level decoding of the close frame
\* (assurance/formal/frame-model.tla), fragmentation and text validation
\* (US-013/US-014), Java's listener re-entrancy and its at-least-once
\* terminal callback (assurance/formal/connection-model.tla, which models
\* that explicitly), wall-clock close timeouts (none exist in the kernel),
\* and every concurrent interleaving (assurance/concurrency/plan.json).
\*
\* DECLARED ABSTRACTIONS, stated plainly.
\* RESTRICTIONS (behaviors the model HIDES):
\*   (1) Close codes are restricted to CloseCodeDomain and reasons to two
\*       classes (empty, text). Each arm of the shipped validity chain has
\*       at least one representative in the domain, and the chain is a
\*       comparison against constants, so each arm is exercised; codes
\*       between the representatives are not enumerated and nothing is
\*       claimed about them.
\*   (2) Inbound close payloads are restricted to six classes, one per arm
\*       of the shipped setPayload plus isValid pipeline. Payload BYTES are
\*       not modeled; the frame model owns the octet level.
\*   (3) Queue capacity, event budgets, and backpressure are not modeled.
\*       Backpressure is the one NON-fatal failure in the port and it
\*       consumes no input and mutates nothing, so omitting it removes only
\*       retry stuttering, never a reachable lifecycle state.
\* ADDITIONS (behaviors the model has that the shipped kernel does not):
\*   (4) The model lets an inbound close arrive in CLOSING even when the
\*       local endpoint initiated the close and the peer already answered.
\*       Real peers cannot always produce that schedule; the extra
\*       schedules can only make the checked invariants harder to satisfy,
\*       never easier.

---- MODULE CloseModel ----
EXTENDS Integers

\* Finite bounds. TerminalBudget bounds the terminal-entry counter so that
\* the double-entry state stays REPRESENTABLE and the at-most-once
\* invariant is therefore falsifiable rather than true by typing.
CONSTANTS TerminalBudget

ASSUME TerminalBudget \in Nat /\ TerminalBudget >= 2

VARIABLES
  state,           \* ReadyState: NotYetConnected / Open / Closing / Closed
  handshakeDone,   \* whether the opening handshake ever completed
  poisoned,        \* set by the first fatal typed failure; absorbing
  closeDetail,     \* the governing close outcome
  terminalEntries, \* number of transitions INTO the absorbing Closed state
  lastInbound,     \* class, outcome kind, and reported code of the last inbound close
  lastOutbound,    \* kind, payload class, and wire code of the last close frame emitted
  lastSend,        \* the last local send_close attempt and its outcome
  refusals         \* whether a state gate has refused an input

vars == <<state, handshakeDone, poisoned, closeDetail, terminalEntries,
          lastInbound, lastOutbound, lastSend, refusals>>

\* ---- domains --------------------------------------------------------------
States == {"NotYetConnected", "Open", "Closing", "Closed"}
Origins == {"none", "local", "remote", "transport"}

\* Every close code the model can hold. -1 is CloseFrame.NEVER_CONNECTED
\* (framing/CloseFrame.java:140), 0 is the "no code reported" sentinel, and
\* the rest are one representative per arm of the shipped validity chain.
CloseCodeDomain == {-1, 0, 1000, 1002, 1004, 1005, 1006, 1007, 1015, 1016, 3000}
SendCodes == {1000, 1002, 1004, 1005, 1007, 1015, 1016, 3000}
ReasonKinds == {"empty", "text"}
ReasonDomain == ReasonKinds \union {"none"}

InboundClasses ==
  {"empty", "one_byte", "code_reason_valid", "code_1007_empty_reason",
   "code_reserved", "invalid_utf8_reason"}
InboundKinds == {"none", "accept", "invalid_data", "runtime_rejection"}
OutboundKinds == {"none", "send_close", "echo_close"}
PayloadClasses == {"none", "constructor", "code_reason"}
SendOutcomes == {"none", "accepted", "rejected"}

NoCloseDetail ==
  [origin |-> "none", code |-> 0, reason |-> "none",
   remote |-> FALSE, hsComplete |-> FALSE]
NoInbound == [class |-> "none", kind |-> "none", code |-> 0]
NoOutbound == [kind |-> "none", payload |-> "none", code |-> 0]
NoSend ==
  [requested |-> 0, normalized |-> 0, reason |-> "none",
   outcome |-> "none", reported |-> 0]

\* ---- the shipped close vocabulary, stated once as pure functions ----------
\* Quirk Q14: CloseFrame.setCode rewrites the TLS_ERROR code 1015 to the
\* NOCODE 1005 BEFORE any validation runs. Java additionally clears the
\* reason at the same site; the port does not (FINDING 1 in the header).
\* JAVA: framing/CloseFrame.java:179-187 setCode: code 1015 becomes 1005 and
\*   the reason is cleared, then updatePayload runs.
NormalizeSendCode(c) == IF c = 1015 THEN 1005 ELSE c

\* Quirk Q13: CloseFrame.isValid's rejection chain, in Java's literal order.
\* Returns the REPORTED close code, or 0 when the pair is wire-legal.
\* JAVA: framing/CloseFrame.java:226-243 isValid: 1007 with an empty reason
\*   reports 1007 (228-230); 1005 with a reason reports 1002 (231-234);
\*   1016..2999 reports 1002 (236-238); 1006/1015/1005/1004, codes below
\*   1000 and above 4999 report 1002 (239-242).
CloseCodeRejection(c, r) ==
  IF c = 1007 /\ r = "empty"
  THEN 1007
  ELSE IF c = 1005 /\ r # "empty"
  THEN 1002
  ELSE IF c > 1015 /\ c < 3000
  THEN 1002
  ELSE IF c = 1006 \/ c = 1015 \/ c = 1005 \/ c = 1004 \/ c > 4999 \/ c < 1000
  THEN 1002
  ELSE 0

\* Quirk Q11: CloseFrame.setPayload's normalization of the inbound payload.
\* JAVA: framing/CloseFrame.java:246-271 setPayload: an empty payload becomes
\*   code 1000 (250-251), a one-octet payload becomes 1002 (252-253), two or
\*   more octets carry the big-endian code (254-261), and an invalid UTF-8
\*   reason sets code 1007 with a null reason (262-269).
InboundCode(class) ==
  CASE class = "empty" -> 1000
    [] class = "one_byte" -> 1002
    [] class = "code_reason_valid" -> 1000
    [] class = "code_1007_empty_reason" -> 1007
    [] class = "code_reserved" -> 1016
    [] class = "invalid_utf8_reason" -> 1007

InboundReason(class) ==
  CASE class = "empty" -> "empty"
    [] class = "one_byte" -> "empty"
    [] class = "code_reason_valid" -> "text"
    [] class = "code_1007_empty_reason" -> "empty"
    [] class = "code_reserved" -> "empty"
    [] class = "invalid_utf8_reason" -> "empty"

\* Quirk Q12: an invalid UTF-8 reason leaves Java's reason field null, and
\* isValid then dereferences it -- a NullPointerException-class rejection
\* with NO close code, which the port reports as JavaRuntimeRejection.
InboundOutcome(class) ==
  IF class = "invalid_utf8_reason"
  THEN [kind |-> "runtime_rejection", code |-> 0]
  ELSE IF CloseCodeRejection(InboundCode(class), InboundReason(class)) # 0
  THEN [kind |-> "invalid_data",
        code |-> CloseCodeRejection(InboundCode(class), InboundReason(class))]
  ELSE [kind |-> "accept", code |-> InboundCode(class)]

InboundAccepts(class) == InboundOutcome(class).kind = "accept"

\* ---- initial state --------------------------------------------------------
Init ==
  /\ state = "NotYetConnected"
  /\ handshakeDone = FALSE
  /\ poisoned = FALSE
  /\ closeDetail = NoCloseDetail
  /\ terminalEntries = 0
  /\ lastInbound = NoInbound
  /\ lastOutbound = NoOutbound
  /\ lastSend = NoSend
  /\ refusals = FALSE

\* ---- pre-handshake arms ---------------------------------------------------
\* JAVA: WebSocketImpl.java:757-766 open(): readyState becomes OPEN at 759
\*   once the handshake is accepted.
OpenHandshake ==
  /\ ~poisoned
  /\ state = "NotYetConnected"
  /\ state' = "Open"
  /\ handshakeDone' = TRUE
  /\ UNCHANGED <<poisoned, closeDetail, terminalEntries, lastInbound,
                 lastOutbound, lastSend, refusals>>

\* A local close before the handshake ever completed runs Java's
\* never-connected ladder: a PROTOCOL_ERROR request keeps 1002, everything
\* else records NEVER_CONNECTED, the reason is preserved, closedremotely is
\* false, and readyState becomes CLOSING. No CloseFrame is built, so neither
\* the Q14 normalization nor the Q13 chain runs on this path.
\* JAVA: WebSocketImpl.java:495-505 close(): the non-OPEN ladder -- 1002 at
\*   498-500, NEVER_CONNECTED at 501, readyState = CLOSING at 503.
PreOpenSendClose(c, r) ==
  /\ ~poisoned
  /\ state = "NotYetConnected"
  /\ closeDetail' = [origin |-> "local",
                     code |-> IF c = 1002 THEN 1002 ELSE -1,
                     reason |-> r, remote |-> FALSE, hsComplete |-> FALSE]
  /\ state' = "Closing"
  /\ UNCHANGED <<handshakeDone, poisoned, terminalEntries, lastInbound,
                 lastOutbound, lastSend, refusals>>

\* Transport EOF before the handshake ever completed reports
\* NEVER_CONNECTED (-1) once and lands in the absorbing Closed state.
\* JAVA: WebSocketImpl.java:608-610 eot(): NOT_YET_CONNECTED calls
\*   closeConnection(NEVER_CONNECTED, true), whose two-argument overload
\*   (569-571) supplies the empty reason.
\* JAVA: WebSocketImpl.java:530-567 closeConnection: the terminal callback
\*   at 557 and readyState = CLOSED at 566.
PreOpenEof ==
  /\ ~poisoned
  /\ state = "NotYetConnected"
  /\ closeDetail' = [origin |-> "transport", code |-> -1, reason |-> "empty",
                     remote |-> TRUE, hsComplete |-> FALSE]
  /\ state' = "Closed"
  /\ terminalEntries' = terminalEntries + 1
  /\ UNCHANGED <<handshakeDone, poisoned, lastInbound, lastOutbound,
                 lastSend, refusals>>

\* ---- local close from OPEN ------------------------------------------------
\* The requested code is normalized (Q14) and then run through the validity
\* chain (Q13). A rejection reports the chain's code, emits NO frame, and
\* does not transition; it is a fatal typed failure, so the kernel poisons.
\* JAVA: framing/CloseFrame.java:226-243 isValid raises InvalidDataException.
\* JAVA: WebSocketImpl.java:481-486 close(): the CloseFrame is built,
\*   setCode runs, and isValid is checked before sendFrame.
SendCloseRejected(c, r) ==
  /\ ~poisoned
  /\ state = "Open"
  /\ CloseCodeRejection(NormalizeSendCode(c), r) # 0
  /\ lastSend' = [requested |-> c, normalized |-> NormalizeSendCode(c),
                  reason |-> r, outcome |-> "rejected",
                  reported |-> CloseCodeRejection(NormalizeSendCode(c), r)]
  /\ poisoned' = TRUE
  /\ UNCHANGED <<state, handshakeDone, closeDetail, terminalEntries,
                 lastInbound, lastOutbound, refusals>>

\* A legal local close emits one close frame carrying the big-endian
\* normalized code and the reason, records the local governing detail, and
\* moves to CLOSING. The terminal state is NOT entered here: the close
\* handshake still needs the peer's answer or an EOF.
\* JAVA: WebSocketImpl.java:481-494 close(): sendFrame then flushAndClose.
\* JAVA: WebSocketImpl.java:584-590 flushAndClose stores the governing close
\*   triple before any terminal delivery.
SendCloseAccepted(c, r) ==
  /\ ~poisoned
  /\ state = "Open"
  /\ CloseCodeRejection(NormalizeSendCode(c), r) = 0
  /\ lastSend' = [requested |-> c, normalized |-> NormalizeSendCode(c),
                  reason |-> r, outcome |-> "accepted", reported |-> 0]
  /\ lastOutbound' = [kind |-> "send_close", payload |-> "code_reason",
                      code |-> NormalizeSendCode(c)]
  /\ closeDetail' = [origin |-> "local", code |-> NormalizeSendCode(c),
                     reason |-> r, remote |-> FALSE, hsComplete |-> FALSE]
  /\ state' = "Closing"
  /\ UNCHANGED <<handshakeDone, poisoned, terminalEntries, lastInbound,
                 refusals>>

\* ---- inbound close from OPEN ----------------------------------------------
\* An accepted inbound close while OPEN records the remote governing detail
\* and echoes a close frame carrying the CONSTRUCTOR payload [0x03, 0xe8]
\* (= 1000), never the received code (ledger sequence 28), then moves to
\* CLOSING.
\* JAVA: drafts/Draft_6455.java:1054-1073 processFrameClosing: CLOSING
\*   completes the handshake through closeConnection, otherwise the TWOWAY
\*   arm echoes through close(code, reason, true).
\* JAVA: framing/CloseFrame.java:168-172 the CloseFrame constructor stores
\*   reason "" and code 1000, which the wire-parsing setPayload override
\*   never replaces in the echoed frame object.
RecvCloseAcceptOpen(class) ==
  /\ ~poisoned
  /\ state = "Open"
  /\ InboundAccepts(class)
  /\ lastInbound' = [class |-> class, kind |-> InboundOutcome(class).kind,
                     code |-> InboundOutcome(class).code]
  /\ closeDetail' = [origin |-> "remote", code |-> InboundOutcome(class).code,
                     reason |-> InboundReason(class), remote |-> TRUE,
                     hsComplete |-> TRUE]
  /\ lastOutbound' = [kind |-> "echo_close", payload |-> "constructor",
                      code |-> 1000]
  /\ state' = "Closing"
  /\ UNCHANGED <<handshakeDone, poisoned, terminalEntries, lastSend,
                 refusals>>

\* A rejected inbound close is a translate-time typed failure: no detail is
\* recorded, no echo is emitted, and the kernel poisons.
\* JAVA: framing/CloseFrame.java:226-243 isValid raises InvalidDataException
\*   during translation, before processFrame ever sees the frame.
RecvCloseRejectedOpen(class) ==
  /\ ~poisoned
  /\ state = "Open"
  /\ ~InboundAccepts(class)
  /\ lastInbound' = [class |-> class, kind |-> InboundOutcome(class).kind,
                     code |-> InboundOutcome(class).code]
  /\ poisoned' = TRUE
  /\ UNCHANGED <<state, handshakeDone, closeDetail, terminalEntries,
                 lastOutbound, lastSend, refusals>>

\* ---- inbound close from CLOSING -------------------------------------------
\* The close handshake completes: the remote detail governs and the
\* connection enters the absorbing Closed state. No echo is emitted.
\* JAVA: drafts/Draft_6455.java:1062-1064 processFrameClosing: the CLOSING
\*   arm calls closeConnection directly.
RecvCloseWhileClosing(class) ==
  /\ ~poisoned
  /\ state = "Closing"
  /\ InboundAccepts(class)
  /\ lastInbound' = [class |-> class, kind |-> InboundOutcome(class).kind,
                     code |-> InboundOutcome(class).code]
  /\ closeDetail' = [origin |-> "remote", code |-> InboundOutcome(class).code,
                     reason |-> InboundReason(class), remote |-> TRUE,
                     hsComplete |-> TRUE]
  /\ state' = "Closed"
  /\ terminalEntries' = terminalEntries + 1
  /\ UNCHANGED <<handshakeDone, poisoned, lastOutbound, lastSend, refusals>>

\* A malformed close arriving in CLOSING is still a translate-time failure.
\* JAVA: framing/CloseFrame.java:226-243 isValid runs during translation
\*   regardless of the connection's readyState.
RecvCloseRejectedWhileClosing(class) ==
  /\ ~poisoned
  /\ state = "Closing"
  /\ ~InboundAccepts(class)
  /\ lastInbound' = [class |-> class, kind |-> InboundOutcome(class).kind,
                     code |-> InboundOutcome(class).code]
  /\ poisoned' = TRUE
  /\ UNCHANGED <<state, handshakeDone, closeDetail, terminalEntries,
                 lastOutbound, lastSend, refusals>>

\* ---- state gates ----------------------------------------------------------
\* Application data after the close handshake started is refused. The port
\* raises its typed state violation, which is fatal, so the kernel poisons.
\* JAVA: WebSocketImpl.java:220-243 decode(): frames are processed only while
\*   OPEN; the CLOSING state does not accept data frames.
RecvDataWhileClosing ==
  /\ ~poisoned
  /\ state = "Closing"
  /\ refusals' = TRUE
  /\ poisoned' = TRUE
  /\ UNCHANGED <<state, handshakeDone, closeDetail, terminalEntries,
                 lastInbound, lastOutbound, lastSend>>

\* Anything at all after the terminal state is refused, and no second
\* terminal entry is produced.
\* JAVA: WebSocketImpl.java:531-533 closeConnection returns immediately once
\*   CLOSED, so no second terminal delivery occurs on that path.
InputAfterClosed ==
  /\ ~poisoned
  /\ state = "Closed"
  /\ refusals' = TRUE
  /\ poisoned' = TRUE
  /\ UNCHANGED <<state, handshakeDone, closeDetail, terminalEntries,
                 lastInbound, lastOutbound, lastSend>>

\* ---- transport EOF after the handshake ------------------------------------
\* Quirk Q20: a CLOSING connection with a governing close echoes that close
\* code and reason; every other post-handshake EOF reports the abnormal
\* close 1006. Either way the connection enters the absorbing Closed state
\* exactly once (ledger sequence 29).
\* JAVA: WebSocketImpl.java:611-612 eot(): the flushandclosestate arm reuses
\*   the stored closecode/closemessage/closedremotely triple.
\* JAVA: WebSocketImpl.java:621-622 eot(): the TWOWAY default arm reports
\*   ABNORMAL_CLOSE.
TransportEof ==
  /\ ~poisoned
  /\ state \in {"Open", "Closing"}
  /\ closeDetail' =
       IF state = "Closing" /\ closeDetail.origin # "none"
       THEN [origin |-> "transport", code |-> closeDetail.code,
             reason |-> closeDetail.reason, remote |-> TRUE,
             hsComplete |-> closeDetail.hsComplete]
       ELSE [origin |-> "transport", code |-> 1006, reason |-> "text",
             remote |-> (state = "Closing"), hsComplete |-> FALSE]
  /\ state' = "Closed"
  /\ terminalEntries' = terminalEntries + 1
  /\ UNCHANGED <<handshakeDone, poisoned, lastInbound, lastOutbound,
                 lastSend, refusals>>

\* ---- terminal stuttering --------------------------------------------------
\* Explicit stuttering so the absorbing states are not reported as
\* deadlocks; TLC's deadlock detection stays at its default (enabled).
\* JAVA: WebSocketImpl.java:531-533 closeConnection is a no-op once CLOSED.
Quiescent ==
  /\ (poisoned \/ (state = "Closed" /\ refusals))
  /\ UNCHANGED vars

Next ==
  \/ OpenHandshake
  \/ \E c \in SendCodes : \E r \in ReasonKinds : PreOpenSendClose(c, r)
  \/ PreOpenEof
  \/ \E c \in SendCodes : \E r \in ReasonKinds : SendCloseRejected(c, r)
  \/ \E c \in SendCodes : \E r \in ReasonKinds : SendCloseAccepted(c, r)
  \/ \E k \in InboundClasses : RecvCloseAcceptOpen(k)
  \/ \E k \in InboundClasses : RecvCloseRejectedOpen(k)
  \/ \E k \in InboundClasses : RecvCloseWhileClosing(k)
  \/ \E k \in InboundClasses : RecvCloseRejectedWhileClosing(k)
  \/ RecvDataWhileClosing
  \/ InputAfterClosed
  \/ TransportEof
  \/ Quiescent

Spec == Init /\ [][Next]_vars

\* Fairness is deliberately narrow: only the actions that RESOLVE a closing
\* connection are weakly fair. Nothing compels a peer to send a close frame
\* or a local caller to request one, exactly as the US-006 connection model
\* gives producer actions no fairness.
ResolveClosing ==
  /\ state = "Closing"
  /\ ~poisoned
  /\ ((\E k \in InboundClasses : RecvCloseWhileClosing(k)) \/ TransportEof)

FairSpec == Spec /\ WF_vars(ResolveClosing)

\* ------------------------- checked state invariants -----------------------
\* Every invariant below is a genuine state predicate: no primed variables,
\* no temporal operators. Each carries a FALSIFIED BY note naming the
\* representable mutation that makes TLC report a violation.

\* FALSIFIED BY: defect.close.type-domain-escape -- change Init's closeDetail
\*   code to 9999, which is outside CloseCodeDomain.
TypeInvariant ==
  /\ state \in States
  /\ handshakeDone \in BOOLEAN
  /\ poisoned \in BOOLEAN
  /\ refusals \in BOOLEAN
  /\ closeDetail.origin \in Origins
  /\ closeDetail.code \in CloseCodeDomain
  /\ closeDetail.reason \in ReasonDomain
  /\ closeDetail.remote \in BOOLEAN
  /\ closeDetail.hsComplete \in BOOLEAN
  /\ terminalEntries \in 0..TerminalBudget
  /\ lastInbound.class \in InboundClasses \union {"none"}
  /\ lastInbound.kind \in InboundKinds
  /\ lastInbound.code \in CloseCodeDomain
  /\ lastOutbound.kind \in OutboundKinds
  /\ lastOutbound.payload \in PayloadClasses
  /\ lastOutbound.code \in CloseCodeDomain
  /\ lastSend.requested \in CloseCodeDomain
  /\ lastSend.normalized \in CloseCodeDomain
  /\ lastSend.reason \in ReasonDomain
  /\ lastSend.outcome \in SendOutcomes
  /\ lastSend.reported \in CloseCodeDomain

\* The absorbing terminal state is entered at most once. terminalEntries
\* deliberately ranges over 0..TerminalBudget with TerminalBudget >= 2 so a
\* double entry is representable and this invariant is falsifiable.
\* FALSIFIED BY: defect.close.double-terminal-entry -- add "Closed" to
\*   TransportEof's enabling state set; TLC then reaches terminalEntries = 2.
TerminalEnteredAtMostOnce == terminalEntries <= 1

\* Reaching the terminal state and entering it are the same event: there is
\* no path into Closed that skips the terminal accounting, and no terminal
\* accounting without Closed.
\* FALSIFIED BY: defect.close.terminal-entry-unaccounted -- in
\*   RecvCloseWhileClosing replace terminalEntries' = terminalEntries + 1
\*   with UNCHANGED terminalEntries.
ClosedIffOneTerminalEntry == (state = "Closed") <=> (terminalEntries = 1)

\* From CLOSING onward a governing close outcome exists: every modeled path
\* into CLOSING or CLOSED records the origin and code that the terminal
\* delivery later reports.
\* FALSIFIED BY: defect.close.closing-without-detail -- in
\*   SendCloseAccepted replace the closeDetail assignment with
\*   UNCHANGED closeDetail.
CloseDetailPresentFromClosing ==
  (state \in {"Closing", "Closed"}) => (closeDetail.origin # "none")

\* The shipped inbound normalization table, restated independently of the
\* receive actions so a mis-normalization on either side is caught rather
\* than being true by construction. The one-byte row is ledger sequence 27
\* (an ACCEPT with code 1002, not a rejection) and the invalid-UTF-8 row is
\* ledger sequence 32 (a runtime rejection with NO reported close code).
\* FALSIFIED BY: defect.close.one-byte-rejected -- change InboundCode's
\*   "one_byte" arm to 1005, which the chain then rejects, turning the
\*   accept row into an invalid_data row.
InboundCloseNormalization ==
  /\ (lastInbound.class = "empty") =>
       (lastInbound.kind = "accept" /\ lastInbound.code = 1000)
  /\ (lastInbound.class = "one_byte") =>
       (lastInbound.kind = "accept" /\ lastInbound.code = 1002)
  /\ (lastInbound.class = "code_reason_valid") =>
       (lastInbound.kind = "accept" /\ lastInbound.code = 1000)
  /\ (lastInbound.class = "code_1007_empty_reason") =>
       (lastInbound.kind = "invalid_data" /\ lastInbound.code = 1007)
  /\ (lastInbound.class = "code_reserved") =>
       (lastInbound.kind = "invalid_data" /\ lastInbound.code = 1002)
  /\ (lastInbound.class = "invalid_utf8_reason") =>
       (lastInbound.kind = "runtime_rejection" /\ lastInbound.code = 0)

\* Ledger sequence 28: the echoed close frame always carries the
\* CONSTRUCTOR payload, whose wire code is 1000, regardless of the received
\* code. This is the invariant that would have caught the RFC-shaped
\* acknowledgement echo.
\* FALSIFIED BY: defect.close.echo-mirrors-received-code -- in
\*   RecvCloseAcceptOpen set the echo's payload to "code_reason" and its
\*   code to InboundOutcome(class).code.
EchoCarriesConstructorPayload ==
  (lastOutbound.kind = "echo_close")
    => (lastOutbound.payload = "constructor" /\ lastOutbound.code = 1000)

\* No close code that the shipped validity chain forbids ever reaches the
\* wire. This is the whole point of running the chain before emitting. The
\* reason carried by each outbound frame is the one the emitting action
\* used: the requested reason for a local close, and the empty constructor
\* reason for an echo.
\* FALSIFIED BY: defect.close.validity-chain-bypassed -- delete the
\*   CloseCodeRejection guard from SendCloseAccepted; TLC then reaches an
\*   outbound frame carrying 1004, 1005, 1015, or 1016.
ForbiddenCodesNeverReachTheWire ==
  /\ (lastOutbound.kind = "send_close")
       => (CloseCodeRejection(lastOutbound.code, lastSend.reason) = 0)
  /\ (lastOutbound.kind = "echo_close")
       => (CloseCodeRejection(lastOutbound.code, "empty") = 0)

\* FINDING 1, checked mechanically: a local close requesting the TLS_ERROR
\* code 1015 is ALWAYS rejected with the reported code 1002, for every
\* reason kind, so the Q14 normalization is observationally inert on this
\* path and the port's omission of Java's reason-clearing side effect
\* changes nothing observable.
\* FALSIFIED BY: defect.close.tls-error-sendable -- delete the
\*   "c = 1015" arm from CloseCodeRejection's fourth clause AND drop
\*   NormalizeSendCode from SendCloseAccepted; 1015 then reaches the wire.
TlsErrorSendAlwaysRejectedAs1002 ==
  (lastSend.requested = 1015)
    => (lastSend.outcome = "rejected" /\ lastSend.reported = 1002)

\* The NEVER_CONNECTED code is a callback-vocabulary code, never a wire
\* code, and it can only be reported before the handshake completed.
\* FALSIFIED BY: defect.close.never-connected-post-handshake -- in
\*   TransportEof's abnormal arm report -1 instead of 1006.
NeverConnectedOnlyPreHandshake ==
  /\ (closeDetail.code = -1) => (~handshakeDone /\ ~closeDetail.hsComplete)
  /\ lastOutbound.code # -1

\* A rejected local close emits no frame and does not move the lifecycle:
\* the failure is reported to the caller and the connection poisons in
\* place (FINDING 2 in the header -- deliberately unlike Java's close(),
\* and bound to the reference model by the US-016 owner amendment).
\* FALSIFIED BY: defect.close.rejected-send-transitions -- add
\*   state' = "Closing" to SendCloseRejected.
RejectedSendDoesNotTransition ==
  (lastSend.outcome = "rejected")
    => (poisoned /\ lastOutbound.kind # "send_close")

\* The fatal-poison flag and the terminal state are independent absorbing
\* facts, and poisoning never fabricates a terminal entry.
\* FALSIFIED BY: defect.close.poison-implies-closed -- add
\*   terminalEntries' = terminalEntries + 1 to RecvCloseRejectedOpen.
PoisonNeverFabricatesTermination ==
  (poisoned /\ state # "Closed") => (terminalEntries = 0)

\* --------------------- checked temporal properties ------------------------
\* These are action and liveness properties and are declared honestly as
\* PROPERTY, never as INVARIANT.

\* CLOSED is absorbing: no modeled transition leaves the terminal state.
\* JAVA: WebSocketImpl.java:531-533 closeConnection early-returns once
\*   CLOSED; no Java path leaves the terminal state.
\* JAVA: enums/ReadyState.java:7 CLOSED is the last lifecycle state.
\* FALSIFIED BY: defect.close.reopen-after-terminal -- add a Reopen action
\*   (state = "Closed" /\\ state' = "Open" /\\ UNCHANGED the rest) to Next.
TerminalAbsorbing == [][(state = "Closed") => (state' = "Closed")]_vars

\* The fatal-poison flag is absorbing and freezes the lifecycle: once a
\* fatal typed failure is reported, no further input changes the state or
\* the governing close outcome. The shipped Java analogue is the
\* InvalidDataException escaping decode into the connection's error path,
\* after which the endpoint never resumes ordinary frame processing.
\* JAVA: WebSocketImpl.java:220-243 decode(): a decode failure leaves the
\*   ordinary processing path and never returns to it.
\* FALSIFIED BY: defect.close.poison-recoverable -- drop the ~poisoned
\*   conjunct from OpenHandshake and TransportEof.
PoisonAbsorbing ==
  [][poisoned => (poisoned' /\ state' = state /\ closeDetail' = closeDetail)]_vars

\* Under the declared fairness, a closing connection that has not suffered a
\* fatal failure always terminates; a poisoned one is allowed to stop,
\* because the kernel's contract is to report and freeze, leaving the
\* transport teardown to the adapter.
\* FALSIFIED BY: defect.close.starved-closing-resolution -- change the cfg
\*   SPECIFICATION from FairSpec to Spec; TLC then finds the lasso that
\*   stutters in CLOSING forever.
ClosingResolves == (state = "Closing") ~> (state = "Closed" \/ poisoned)

====
