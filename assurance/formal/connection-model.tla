\* US-006 abstract connection lifecycle model for the verified Java-WebSocket
\* port (Claude plane). Authority: the pinned quarantined Java-WebSocket 1.6.0
\* tree at .quarantine/Java-WebSocket-da3cf2a777aed862f2f5b5cf060cae7969958667/
\* src/main/java/org/java_websocket/ (all \* JAVA: citations below are
\* package-root-relative file:line references into that tree, each verified by
\* direct read), carrying the US-005 close-code semantics with two distinct
\* evidence bases (evidence/corpus-calibration.json, status LIVE_CALIBRATED):
\* (1) REJECTION-path close codes: the jm-close-code-1000 Java behavioral
\* mutant rewrites only the InvalidDataException catch to report 1000, and its
\* 71 kills (19+26+26 across tiers, signature "close_code 1000, expected
\* 1002/1007/1009") live-confirm that the rejection-path codes the runtime
\* emits are distinguishable from 1000 -- nothing more. (2) ACCEPT-path
\* normalization, including empty-payload-close -> 1000: confirmed by direct
\* source read of CloseFrame.setPayload (framing/CloseFrame.java:250-251);
\* the mutant never exercises this path because an empty close is accepted
\* and never enters the rewritten catch.
\*
\* STAGE AS: ConnectionModel.tla -- TLA+ module identifiers cannot contain a
\* hyphen, so a TLC run must stage this file as ConnectionModel.tla and
\* connection-model.cfg as ConnectionModel.cfg in a scratch directory:
\*   cp connection-model.tla ConnectionModel.tla
\*   cp connection-model.cfg ConnectionModel.cfg
\*   java -cp tla2tools.jar tlc2.TLC -config ConnectionModel.cfg ConnectionModel
\*
\* MODEL_CHECK: MODEL_CHECK_PENDING_TOOL -- TLC is not installed on the
\* authoring host. Probes actually run on 2026-08-26 (darwin/arm64):
\*   command -v tlc                                        -> no output, exit 1
\*   command -v tla2tools                                  -> no output, exit 1
\*   brew list | grep -i -E 'tla|apalache'                 -> no output
\*   ls ~/.m2/repository | grep -i tla                     -> no output
\*   mdfind -name tla2tools                                -> no output
\*   find ~ /opt /usr/local -maxdepth 4 -iname 'tla2tools*.jar' -> no output
\* Java 17.0.19 (Homebrew OpenJDK) is present, so the staged TLC command above
\* is executable as soon as tla2tools.jar is provisioned inside the accepted
\* US-007 sbx profile. No model-check result is claimed here.
\*
\* CLAIM CEILING: proved-model only (PRD US-006 AC4). This model abstracts the
\* shipped Java connection lifecycle; it establishes nothing about production
\* Rust without a reviewed composition/refinement link, and no proof-only
\* duplicate implementation exists or is permitted (the model is specification
\* language only).
\*
\* MODEL SCOPE: the model covers the serialized observable lifecycle. Racy
\* Java interleavings (send-vs-close, reset-vs-decode, timer-vs-worker,
\* handshake-buffer-vs-close) are deliberately NOT modeled here; they are
\* classified as not-corpus-encodable in assurance/concurrency/plan.json and
\* the port serializes them by construction. The model's deliberate
\* abstractions relative to Java fall into two honestly distinct kinds:
\*
\* RESTRICTIONS (behaviors of Java the model HIDES): the outbound queue is
\* finitely bounded via QueueCapacity although Java's outQueue is unbounded
\* (declared WebSocketImpl.java:98, constructed as an unbounded
\* LinkedBlockingQueue at :206) -- SendData is disabled at capacity, so every Java
\* behavior in which more writes are simultaneously queued does not exist in
\* the model; likewise MaxSends and MaxInbound cut off longer send/receive
\* histories. This is the standard finite-state abstraction, and its
\* implication is stated plainly: the checked safety results hold only for
\* behaviors within these bounds, and the model claims nothing about
\* behaviors beyond them. Bounding an unbounded queue is NOT a
\* safety-preserving widening. (The PORT's bounded queue is a separate,
\* deliberate design divergence with its own recorded pointer,
\* divergence.bounded-command-queue in behavior_delta_ledger of
\* assurance/concurrency/plan.json.)
\*
\* RESTRICTION (declared, close-delivery scope): listener re-entrancy is NOT
\* represented. The model is a single-threaded serialized abstraction with no
\* reentrant callback edges -- no action fires from inside a callback, so no
\* modeled transition re-enters the close path from inside onWebsocketClose.
\* Within this restriction terminal delivery is exactly-once and the
\* TerminalDeliveredAtMostOnce invariant holds. Shipped Java is WEAKER: the
\* closeConnection monitor is reentrant (synchronized, WebSocketImpl.java:530)
\* and the terminal onWebsocketClose callback (557) fires BEFORE readyState =
\* CLOSED (566), so a listener that re-enters closeConnection from inside the
\* callback passes the readyState guard (531-533) and receives a second
\* terminal callback: the shipped observable semantics are AT-LEAST-ONCE
\* terminal delivery (proof-targets target.formal.close.terminal-absorbing).
\* The invariant is therefore scoped to this declared restriction and is NOT
\* a claim about unrestricted Java. Exactly-once delivery in the port is a
\* planned PORT-side strengthening, recorded as
\* note.close.exactly-once-terminal-delivery in
\* assurance/formal/proof-targets.json and pending its behavior-delta ledger
\* entry (US-009); it is never asserted here as a Java parity fact.
\*
\* ADDITIONS (behaviors the model has that serialized Java does not): (1) the
\* translate-stage and process-stage of truncated-tail text rejection are
\* split into two atomic actions although Java performs both inside one
\* decodeFrames call (WebSocketImpl.java:390-397); other actions firing
\* inside that window model the processing of earlier frames of the same
\* translated batch, plus orderings serialized Java cannot produce at all
\* (e.g. a local close between the stages). (2) CloseOnDrain is enabled from
\* any CLOSING state although Java gates it on the flushandclosestate latch;
\* every modeled path into CLOSING passes a flushAndClose call site, so this
\* relaxation only adds schedules. Additions can only make the checked
\* invariants harder to satisfy, never easier.
\*
\* MECHANIZED CHECK: internal/formalplan/model_walker_test.go carries a
\* hand-translated Go replica of this transition relation and exhaustively
\* enumerates the reachable states under the shipped cfg bounds, checking
\* every INVARIANT plus the TerminalAbsorbing action property, and executing
\* the seeded mutations to confirm non-vacuity. The walker verifies this
\* RESTRICTED model (no listener re-entrancy, see MODEL SCOPE above); its
\* results inherit the same restriction and say nothing about unrestricted
\* Java. It is a test of this
\* artifact, not TLC: it does not parse this file (translation divergence is
\* a residual risk), and it does not check the ClosingLeadsToClosed liveness
\* property, which remains pending the TLC run recorded below.
---- MODULE ConnectionModel ----
EXTENDS Integers, Sequences

\* Finite bounds. All counters and queues are bounded through these
\* constants; the shipped connection-model.cfg assigns concrete small values,
\* so the reachable state space is finite by construction (no unbounded Nat).
CONSTANTS QueueCapacity, MaxSends, MaxInbound

ASSUME QueueCapacity \in Nat /\ QueueCapacity >= 1
ASSUME MaxSends \in Nat /\ MaxSends >= 1
ASSUME MaxInbound \in Nat /\ MaxInbound >= 1

VARIABLES
  state,                \* ReadyState: enums/ReadyState.java:7 (NOT_YET_CONNECTED, OPEN, CLOSING, CLOSED)
  outQ,                 \* abstract outbound write queue (WebSocketImpl.outQueue)
  sendCount,            \* bounded count of accepted send commands
  inboundCount,         \* bounded count of consumed inbound frames
  terminalDeliveries,   \* onWebsocketClose deliveries observed (at-most-once under the declared no-re-entrancy restriction, see MODEL SCOPE)
  closeDetail,          \* origin/code of the governing close outcome
  lastInboundClose,     \* payload class and normalized outcome of the last inbound close frame
  pendingProcessReject, \* truncated-tail text recorded at translate stage, strict reject pending
  droppedWrites,        \* writes discarded when the connection tore down
  rejectedLocalCloses   \* local close attempts rejected by CloseFrame.isValid

vars == <<state, outQ, sendCount, inboundCount, terminalDeliveries,
          closeDetail, lastInboundClose, pendingProcessReject,
          droppedWrites, rejectedLocalCloses>>

\* Domains. Close codes are the normalized codes reachable in this
\* abstraction: -1 is CloseFrame.NEVER_CONNECTED (eot before the handshake,
\* WebSocketImpl.java:609-610), 0 is the not-set sentinel, 1000/1002/1006/1007
\* are the normalization outcomes (rejection codes live-confirmed by the
\* mutant kills; accept-path codes source-read, see the header).
States == {"Connecting", "Open", "Closing", "Closed"}
WriteKinds == {"data", "close"}
CloseCodes == {-1, 0, 1000, 1002, 1006, 1007}
Origins == {"none", "local", "remote", "transport", "error"}
AcceptClasses == {"empty", "one_byte", "valid_code_reason"}
InvalidDataClasses == {"code_1007_empty_reason", "reserved_or_invalid_code"}
InboundCloseClasses ==
  AcceptClasses \union InvalidDataClasses \union {"invalid_utf8_reason"}
OutcomeKinds == {"none", "accept", "invalid_data", "runtime_rejection"}

NoCloseDetail == [origin |-> "none", code |-> 0]
NoInboundClose == [class |-> "none", kind |-> "none", code |-> 0]

\* Inbound close-payload normalization, mirroring CloseFrame.setPayload then
\* CloseFrame.isValid. This table is duplicated deliberately: the receive
\* actions below assign these outcomes inline, and the invariant
\* InboundCloseNormalization restates the table, so a mutation to either side
\* is caught by TLC rather than being true by construction.
\* JAVA: framing/CloseFrame.java:246-273 setPayload: empty payload -> code
\*   1000 (NORMAL, line 250-251; confirmed by direct source read -- the
\*   jm-close-code-1000 mutant never exercises this accept path), one
\*   byte -> 1002 (PROTOCOL_ERROR, 252-253), >=2 bytes -> big-endian code
\*   (254-261), invalid UTF-8 reason -> code 1007 with null reason (262-269).
\* JAVA: framing/CloseFrame.java:226-243 isValid rejection chain: 1007 with
\*   empty reason -> throw 1007 (228-230); 1005-with-reason -> 1002 (231-234);
\*   1016..2999 -> 1002 (236-238); 1006/1015/1005/<1000/1004/>4999 -> 1002
\*   (239-242).
AcceptCode(c) ==
  CASE c = "empty" -> 1000
    [] c = "one_byte" -> 1002
    [] c = "valid_code_reason" -> 1000

InvalidDataCode(c) ==
  CASE c = "code_1007_empty_reason" -> 1007
    [] c = "reserved_or_invalid_code" -> 1002

Init ==
  /\ state = "Connecting"
  /\ outQ = <<>>
  /\ sendCount = 0
  /\ inboundCount = 0
  /\ terminalDeliveries = 0
  /\ closeDetail = NoCloseDetail
  /\ lastInboundClose = NoInboundClose
  /\ pendingProcessReject = FALSE
  /\ droppedWrites = 0
  /\ rejectedLocalCloses = 0

\* JAVA: WebSocketImpl.java:757-766 open(): readyState = OPEN at 759 after
\*   the server handshake acceptance path in decodeHandshake completes.
OpenHandshake ==
  /\ state = "Connecting"
  /\ state' = "Open"
  /\ UNCHANGED <<outQ, sendCount, inboundCount, terminalDeliveries,
                 closeDetail, lastInboundClose, pendingProcessReject,
                 droppedWrites, rejectedLocalCloses>>

\* JAVA: WebSocketImpl.java:736-742 write(): every send enqueues onto
\*   outQueue and signals onWriteDemand; WebSocketImpl.java:749-755 the
\*   multi-buffer variant is atomic under synchronizeWriteObject (seam L1).
\*   Java's queue is unbounded (seam Q1); the Len guard here is the model's
\*   finite bound and the port's deliberate bounded-queue divergence
\*   (behavior_delta_ledger pointer divergence.bounded-command-queue).
SendData ==
  /\ state = "Open"
  /\ sendCount < MaxSends
  /\ Len(outQ) < QueueCapacity
  /\ outQ' = Append(outQ, "data")
  /\ sendCount' = sendCount + 1
  /\ UNCHANGED <<state, inboundCount, terminalDeliveries, closeDetail,
                 lastInboundClose, pendingProcessReject, droppedWrites,
                 rejectedLocalCloses>>

\* JAVA: WebSocketImpl.java:220-243 decode(): frames are decoded only in
\*   OPEN (gate at 228-229); Draft_6455.java:893-918 processFrame dispatches
\*   text/binary to the message callbacks (956-963, 982-990).
RecvDataFrame ==
  /\ state = "Open"
  /\ inboundCount < MaxInbound
  /\ inboundCount' = inboundCount + 1
  /\ UNCHANGED <<state, outQ, sendCount, terminalDeliveries, closeDetail,
                 lastInboundClose, pendingProcessReject, droppedWrites,
                 rejectedLocalCloses>>

\* Stage one of the two-stage truncated-tail semantics: the translate-time
\* Hoehrmann DFA only fails in its error state, so a text payload ending in a
\* valid-but-incomplete multi-byte prefix is ACCEPTED at translate time and
\* the frame is recorded.
\* JAVA: framing/TextFrame.java:45-49 isValid() -> Charsetfunctions.isValidUTF8
\* JAVA: util/Charsetfunctions.java:129-151 the DFA accept-or-incomplete check
\* JAVA: drafts/Draft_6455.java:595 translateSingleFrame runs frame.isValid()
RecvTextTruncatedTail ==
  /\ state = "Open"
  /\ pendingProcessReject = FALSE
  /\ inboundCount < MaxInbound
  /\ inboundCount' = inboundCount + 1
  /\ pendingProcessReject' = TRUE
  /\ UNCHANGED <<state, outQ, sendCount, terminalDeliveries, closeDetail,
                 lastInboundClose, droppedWrites, rejectedLocalCloses>>

\* Stage two: the strict REPORT decoder rejects the recorded truncated tail
\* at process time with close code 1007, and the invalid-data close path
\* emits a close frame and enters CLOSING. Java performs both stages inside
\* one decodeFrames call; the model splits them to expose the
\* recorded-then-rejected ordering (a deliberate ADDITION of interleavings,
\* see MODEL SCOPE). This action requires state = "Open": once a close has
\* begun, the staged rejection is discarded by the close actions below,
\* because Java's close() no-ops when already CLOSING (WebSocketImpl.java:
\* 463-464) -- see TruncatedTailStaging.
\* JAVA: drafts/Draft_6455.java:982-990 processFrameText -> stringUtf8
\* JAVA: util/Charsetfunctions.java:68-90 stringUtf8 strict decode throws 1007
\* JAVA: WebSocketImpl.java:391-418 decodeFrames catches InvalidDataException
\*   (405-408) -> onWebsocketError + close(e)
\* JAVA: WebSocketImpl.java:463-507 close() sends the 1007 close frame while
\*   still open (481-487) and transitions to CLOSING (503)
ProcessRejectTruncatedTail ==
  /\ state = "Open"
  /\ pendingProcessReject = TRUE
  /\ Len(outQ) < QueueCapacity
  /\ pendingProcessReject' = FALSE
  /\ state' = "Closing"
  /\ closeDetail' = [origin |-> "error", code |-> 1007]
  /\ outQ' = Append(outQ, "close")
  /\ UNCHANGED <<sendCount, inboundCount, terminalDeliveries,
                 lastInboundClose, droppedWrites, rejectedLocalCloses>>

\* Inbound close frame whose payload class normalizes to an accepted code.
\* While OPEN, Java echoes the close handshake and enters CLOSING.
\* JAVA: drafts/Draft_6455.java:1054-1073 processFrameClosing: not yet
\*   CLOSING -> TWOWAY echo via close(code, reason, true) at 1067-1068
\* JAVA: WebSocketImpl.java:463-507 close(): echo close frame sent at
\*   481-487, readyState = CLOSING at 503
\* JAVA: framing/CloseFrame.java:246-273 setPayload normalization (empty ->
\*   1000 per the 250-251 source read; the mutant kills confirm only the
\*   rejection-path codes)
\* Discard semantics: a truncated tail staged at translate time is dropped as
\* a close outcome when a close begins. In Java the tail (a later frame of
\* the same translated batch, WebSocketImpl.java:390-397) is still processed
\* after this close frame put the connection into CLOSING -- processFrame has
\* no readyState gate (drafts/Draft_6455.java:893-918) and stringUtf8 still
\* throws 1007 -- but the resulting close(e) (WebSocketImpl.java:408,
\* 631-633) is a complete no-op because close() early-returns once CLOSING
\* (WebSocketImpl.java:463-464). Its only residue is an onWebsocketError
\* callback, which this abstraction does not track.
RecvCloseAccept(c) ==
  /\ state = "Open"
  /\ c \in AcceptClasses
  /\ inboundCount < MaxInbound
  /\ Len(outQ) < QueueCapacity
  /\ inboundCount' = inboundCount + 1
  /\ lastInboundClose' = [class |-> c, kind |-> "accept", code |-> AcceptCode(c)]
  /\ closeDetail' = [origin |-> "remote", code |-> AcceptCode(c)]
  /\ outQ' = Append(outQ, "close")
  /\ state' = "Closing"
  /\ pendingProcessReject' = FALSE
  /\ UNCHANGED <<sendCount, terminalDeliveries, droppedWrites,
                 rejectedLocalCloses>>

\* Inbound close frame rejected by CloseFrame.isValid: the
\* InvalidDataException carries 1007 (NO_UTF8 code with empty reason) or 1002
\* (reserved/invalid codes), and the error-close path emits a close frame
\* with that code and enters CLOSING.
\* JAVA: framing/CloseFrame.java:226-243 the isValid rejection chain
\* JAVA: drafts/Draft_6455.java:595 frame.isValid() at translate time
\* JAVA: WebSocketImpl.java:391-418 decodeFrames catch -> close(e) at 405-408
\* JAVA: WebSocketImpl.java:463-507 close() -> CLOSING at 503
\* Discard semantics for a staged truncated tail: same as RecvCloseAccept
\* (close() no-ops once CLOSING, WebSocketImpl.java:463-464).
RecvCloseInvalidData(c) ==
  /\ state = "Open"
  /\ c \in InvalidDataClasses
  /\ inboundCount < MaxInbound
  /\ Len(outQ) < QueueCapacity
  /\ inboundCount' = inboundCount + 1
  /\ lastInboundClose' = [class |-> c, kind |-> "invalid_data", code |-> InvalidDataCode(c)]
  /\ closeDetail' = [origin |-> "error", code |-> InvalidDataCode(c)]
  /\ outQ' = Append(outQ, "close")
  /\ state' = "Closing"
  /\ pendingProcessReject' = FALSE
  /\ UNCHANGED <<sendCount, terminalDeliveries, droppedWrites,
                 rejectedLocalCloses>>

\* Inbound close whose >=2-byte payload carries an invalid UTF-8 reason:
\* setPayload stores code 1007 with a NULL reason, and isValid's
\* reason.isEmpty() then throws NullPointerException. RuntimeException is not
\* caught by decodeFrames (WebSocketImpl.java:391-418 catches only
\* InvalidDataException/LimitExceededException/Error), and the server worker
\* swallows it: doDecode catches Exception and only logs, so the connection
\* stays OPEN. This is the corpus JAVA_RUNTIME_REJECTION outcome.
\* JAVA: framing/CloseFrame.java:262-269 code = NO_UTF8, reason = null
\* JAVA: framing/CloseFrame.java:228-230 reason.isEmpty() on null -> NPE
\* JAVA: server/WebSocketServer.java:1163-1169 doDecode catches Exception and
\*   logs "Error while reading from remote connection"; no close is initiated
\* Staged-tail note: this action leaves pendingProcessReject unchanged. In
\* same-batch Java the NPE aborts translateFrame before the process loop, so
\* a tail staged in that batch would be lost with the whole frames list; the
\* model keeping the staged reject (and later closing 1007) is one of the
\* declared ADDED interleavings, not a Java-reachable ordering.
RecvCloseUtf8ReasonRuntimeRejection ==
  /\ state = "Open"
  /\ inboundCount < MaxInbound
  /\ inboundCount' = inboundCount + 1
  /\ lastInboundClose' = [class |-> "invalid_utf8_reason",
                          kind |-> "runtime_rejection", code |-> 0]
  /\ UNCHANGED <<state, outQ, sendCount, terminalDeliveries, closeDetail,
                 pendingProcessReject, droppedWrites, rejectedLocalCloses>>

\* Local close with a wire-legal code: the close frame passes
\* CloseFrame.isValid, is sent, and the connection enters CLOSING.
\* JAVA: WebSocketImpl.java:463-507 close(): onWebsocketCloseInitiated for
\*   local closes (474-479), close frame built/validated/sent (481-487),
\*   flushAndClose stores the code/reason/remote triple (494; 584-606), and
\*   readyState = CLOSING at 503.
\* Discard semantics for a staged truncated tail: serialized Java cannot run
\* a local close between the two stages at all (both live inside one
\* decodeFrames call, WebSocketImpl.java:390-397; the cross-thread case is
\* race.send_vs_close territory, out of model scope), so this ordering is a
\* model-added interleaving; its outcome mirrors Java's already-CLOSING
\* behavior, where the tail's close(e) no-ops (WebSocketImpl.java:463-464)
\* and the staged rejection never governs the close outcome.
LocalCloseValid ==
  /\ state = "Open"
  /\ Len(outQ) < QueueCapacity
  /\ closeDetail' = [origin |-> "local", code |-> 1000]
  /\ outQ' = Append(outQ, "close")
  /\ state' = "Closing"
  /\ pendingProcessReject' = FALSE
  /\ UNCHANGED <<sendCount, inboundCount, terminalDeliveries,
                 lastInboundClose, droppedWrites, rejectedLocalCloses>>

\* Local close with a code CloseFrame.isValid rejects (for example 1015,
\* which setCode first normalizes to 1005 and isValid then rejects): the
\* generated frame is invalid, no close frame is sent, and Java falls back to
\* flushAndClose(ABNORMAL_CLOSE=1006) before entering CLOSING.
\* JAVA: framing/CloseFrame.java:179-184 setCode: TLS_ERROR 1015 -> NOCODE
\* JAVA: framing/CloseFrame.java:226-243 isValid rejects NOCODE and friends
\* JAVA: WebSocketImpl.java:488-492 catch InvalidDataException ->
\*   flushAndClose(CloseFrame.ABNORMAL_CLOSE, "generated frame is invalid")
\* JAVA: WebSocketImpl.java:503 readyState = CLOSING
\* Discard semantics for a staged truncated tail: same rationale as
\* LocalCloseValid (WebSocketImpl.java:463-464).
LocalCloseInvalidCode ==
  /\ state = "Open"
  /\ rejectedLocalCloses < 1
  /\ rejectedLocalCloses' = rejectedLocalCloses + 1
  /\ closeDetail' = [origin |-> "error", code |-> 1006]
  /\ state' = "Closing"
  /\ pendingProcessReject' = FALSE
  /\ UNCHANGED <<outQ, sendCount, inboundCount, terminalDeliveries,
                 lastInboundClose, droppedWrites>>

\* JAVA: SocketChannelIOHelper.java:82-115 batch(): the selector thread
\*   drains outQueue head-first in FIFO order (97-107); the OP_WRITE re-arm
\*   loop is server/WebSocketServer.java:848-857 with the write path at
\*   583-592.
FlushWrite ==
  /\ state \in {"Open", "Closing"}
  /\ Len(outQ) > 0
  /\ outQ' = Tail(outQ)
  /\ UNCHANGED <<state, sendCount, inboundCount, terminalDeliveries,
                 closeDetail, lastInboundClose, pendingProcessReject,
                 droppedWrites, rejectedLocalCloses>>

\* Receiving the peer's close while already CLOSING completes the handshake:
\* closeConnection cancels the key, closes the channel, delivers
\* onWebsocketClose (once in this model under its declared no-re-entrancy
\* restriction; shipped Java is at-least-once under listener re-entry, see
\* MODEL SCOPE), and reaches CLOSED. Writes still queued at key-cancel are
\* dropped.
\* JAVA: drafts/Draft_6455.java:1062-1064 processFrameClosing while CLOSING
\*   -> closeConnection(code, reason, true)
\* JAVA: WebSocketImpl.java:530-567 closeConnection: onWebsocketClose at 557,
\*   draft.reset() at 562-564, readyState = CLOSED at 566
\* JAVA: server/WebSocketServer.java:848-857 CancelledKeyException ->
\*   outQueue.clear() at 852-854 (silent drop; recorded divergence pointer
\*   divergence.silent-drop-on-close)
RecvCloseWhileClosing ==
  /\ state = "Closing"
  /\ inboundCount < MaxInbound
  /\ inboundCount' = inboundCount + 1
  /\ lastInboundClose' = [class |-> "empty", kind |-> "accept", code |-> 1000]
  /\ closeDetail' = [origin |-> "remote", code |-> 1000]
  /\ state' = "Closed"
  /\ terminalDeliveries' = terminalDeliveries + 1
  /\ droppedWrites' = Len(outQ)
  /\ outQ' = <<>>
  /\ pendingProcessReject' = FALSE
  /\ UNCHANGED <<sendCount, rejectedLocalCloses>>

\* Server-side close-after-drain: once the queue is flushed and flushAndClose
\* has latched, the selector thread calls the no-argument closeConnection,
\* which replays the stored code/reason/remote triple into the terminal
\* delivery. The model over-approximates by enabling this from any CLOSING
\* state (in Java the flushandclosestate latch gates it; every modeled path
\* into CLOSING passes through a flushAndClose call site).
\* JAVA: SocketChannelIOHelper.java:110-113 outQueue empty + isFlushAndClose
\*   + server role -> ws.closeConnection()
\* JAVA: WebSocketImpl.java:573-578 closeConnection() replays the stored
\*   closecode/closemessage/closedremotely (fields at 154-156, seam R3)
\* JAVA: WebSocketImpl.java:530-567 terminal transition as above
CloseOnDrain ==
  /\ state = "Closing"
  /\ Len(outQ) = 0
  /\ state' = "Closed"
  /\ terminalDeliveries' = terminalDeliveries + 1
  /\ pendingProcessReject' = FALSE
  /\ UNCHANGED <<outQ, sendCount, inboundCount, closeDetail,
                 lastInboundClose, droppedWrites, rejectedLocalCloses>>

\* Transport EOF. Before the handshake completes, eot() closes with
\* NEVER_CONNECTED (-1); in OPEN with the TWOWAY close handshake it closes
\* abnormally with 1006; while CLOSING with the flush-and-close latch set it
\* replays the stored close code. Queued writes are dropped at key-cancel.
\* JAVA: WebSocketImpl.java:608-624 eot(): NOT_YET_CONNECTED ->
\*   closeConnection(NEVER_CONNECTED, true) at 609-610; flushandclosestate ->
\*   closeConnection(closecode, closemessage, closedremotely) at 611-612;
\*   TWOWAY default -> closeConnection(ABNORMAL_CLOSE, true) at 622-623
\* JAVA: SocketChannelIOHelper.java:45-48 read EOF dispatches ws.eot()
\* JAVA: WebSocketImpl.java:530-567 terminal transition: onWebsocketClose at
\*   557 precedes CLOSED at 566 (at-least-once under listener re-entry;
\*   modeled once under the declared no-re-entrancy restriction)
TransportEOF ==
  /\ state \in {"Connecting", "Open", "Closing"}
  /\ closeDetail' =
       IF state = "Closing"
       THEN [origin |-> "transport", code |-> closeDetail.code]
       ELSE IF state = "Connecting"
            THEN [origin |-> "transport", code |-> -1]
            ELSE [origin |-> "transport", code |-> 1006]
  /\ state' = "Closed"
  /\ terminalDeliveries' = terminalDeliveries + 1
  /\ droppedWrites' = Len(outQ)
  /\ outQ' = <<>>
  /\ pendingProcessReject' = FALSE
  /\ UNCHANGED <<sendCount, inboundCount, lastInboundClose,
                 rejectedLocalCloses>>

\* Explicit terminal stuttering: CLOSED is absorbing, not a deadlock. TLC's
\* default deadlock detection stays enabled because this action is always
\* enabled in the terminal state.
\* JAVA: WebSocketImpl.java:531-533 closeConnection returns immediately once
\*   CLOSED; enums/ReadyState.java:7 CLOSED is the last lifecycle state.
Done ==
  /\ state = "Closed"
  /\ UNCHANGED vars

Next ==
  \/ OpenHandshake
  \/ SendData
  \/ RecvDataFrame
  \/ RecvTextTruncatedTail
  \/ ProcessRejectTruncatedTail
  \/ \E c \in AcceptClasses : RecvCloseAccept(c)
  \/ \E c \in InvalidDataClasses : RecvCloseInvalidData(c)
  \/ RecvCloseUtf8ReasonRuntimeRejection
  \/ LocalCloseValid
  \/ LocalCloseInvalidCode
  \/ FlushWrite
  \/ RecvCloseWhileClosing
  \/ CloseOnDrain
  \/ TransportEOF
  \/ Done

Spec == Init /\ [][Next]_vars

\* Fairness is deliberately narrow: only closing resolution and flushing are
\* weakly fair. Producer actions carry NO fairness, mirroring the deliberate
\* PRODUCER_ADMISSION_FAIRNESS_ABSENT declaration in
\* assurance/concurrency/plan.json (Java's unbounded outQueue admits no
\* fairness among senders either).
ResolveClosing ==
  /\ state = "Closing"
  /\ (RecvCloseWhileClosing \/ CloseOnDrain \/ TransportEOF)

FairSpec == Spec /\ WF_vars(ResolveClosing) /\ WF_vars(FlushWrite)

\* ------------------------- checked state invariants -----------------------
\* Every invariant below is a genuine state predicate: no primed variables,
\* no temporal operators. Each carries a FALSIFIED BY note naming the
\* representable mutation that makes TLC report a violation; the same
\* mutations are frozen as the seeded-defect table in
\* assurance/concurrency/plan.json.

\* FALSIFIED BY: defect.model.type-domain-escape -- change Init's closeDetail
\*   to [origin |-> "none", code |-> 5]; 5 is outside CloseCodes.
TypeInvariant ==
  /\ state \in States
  /\ \A i \in DOMAIN outQ : outQ[i] \in WriteKinds
  /\ sendCount \in 0..MaxSends
  /\ inboundCount \in 0..MaxInbound
  /\ terminalDeliveries \in 0..2
  /\ closeDetail \in [origin : Origins, code : CloseCodes]
  /\ lastInboundClose \in [class : InboundCloseClasses \union {"none"},
                           kind : OutcomeKinds, code : CloseCodes]
  /\ pendingProcessReject \in BOOLEAN
  /\ droppedWrites \in 0..QueueCapacity
  /\ rejectedLocalCloses \in 0..1

\* The terminal event is delivered at most once WITHIN THE DECLARED
\* NO-RE-ENTRANCY RESTRICTION (see MODEL SCOPE): the model has no reentrant
\* callback edges, so at-most-once delivery holds here by that restriction.
\* This invariant is NOT a claim about unrestricted shipped Java, which
\* delivers AT-LEAST-ONCE under listener re-entry: onWebsocketClose fires at
\* WebSocketImpl.java:557 BEFORE readyState = CLOSED at 566 under the
\* reentrant monitor at 530, so Java's monitor plus CLOSED guard give
\* single delivery only across threads and for listeners that do not
\* re-enter the close path. Exactly-once delivery in the port is the planned
\* strengthening note.close.exactly-once-terminal-delivery (US-017 AC2),
\* pending its behavior-delta ledger entry.
\* terminalDeliveries deliberately ranges over 0..2 in TypeInvariant so the
\* double-delivery state is representable and this invariant is falsifiable.
\* FALSIFIED BY: defect.model.double-terminal-delivery -- add "Closed" to
\*   TransportEOF's enabling state set; TLC then reaches
\*   terminalDeliveries = 2.
TerminalDeliveredAtMostOnce == terminalDeliveries <= 1

\* Every closed connection delivered its terminal event exactly once within
\* the declared no-re-entrancy restriction (formal.connection.no-terminal-
\* escape: no modeled path reaches CLOSED without the onWebsocketClose
\* delivery at WebSocketImpl.java:557; shipped Java is at-least-once under
\* listener re-entry -- see MODEL SCOPE).
\* FALSIFIED BY: defect.model.closed-without-terminal-event -- in
\*   CloseOnDrain replace terminalDeliveries' = terminalDeliveries + 1 with
\*   UNCHANGED terminalDeliveries.
ClosedImpliesTerminalDeliveredOnce ==
  (state = "Closed") => (terminalDeliveries = 1)

\* From CLOSING onward a governing close outcome exists: every modeled path
\* into CLOSING records the code/origin that flushAndClose stores
\* (WebSocketImpl.java:588-590) and closeConnection later delivers.
\* FALSIFIED BY: defect.model.closing-without-close-detail -- in
\*   LocalCloseValid replace the closeDetail assignment with
\*   UNCHANGED closeDetail.
CloseDetailPresentFromClosing ==
  (state \in {"Closing", "Closed"}) => (closeDetail.origin # "none")

\* Error-origin closes carry only the codes the Java error paths produce:
\* 1002/1007 from InvalidDataException handling, 1006 from the
\* invalid-generated-frame fallback.
\* FALSIFIED BY: defect.model.error-close-with-normal-code -- in
\*   ProcessRejectTruncatedTail set the code to 1000.
ErrorCloseCodeDomain ==
  (closeDetail.origin = "error") => (closeDetail.code \in {1002, 1006, 1007})

\* The CloseFrame normalization table, restated independently of the receive
\* actions so a mis-normalization mutation on either side is caught. Evidence
\* split (see header): the rejection-path rows (1007-empty-reason,
\* reserved/invalid codes) are live-confirmed by the jm-close-code-1000
\* mutant's 71 kills, whose signature proves the runtime's rejection codes
\* are distinguishable from 1000; the accept-path rows, including
\* empty -> 1000, rest on the direct source read of
\* framing/CloseFrame.java:246-273, which the mutant cannot exercise (an
\* empty close never enters the rewritten InvalidDataException catch).
\* FALSIFIED BY: defect.model.empty-close-misnormalized -- in
\*   RecvCloseAccept assign code 1002 for the "empty" class (the historical
\*   B1-style empty-close mis-normalization; guarded by the
\*   CloseFrame.java:250-251 source read, NOT by the mutant kills).
InboundCloseNormalization ==
  /\ (lastInboundClose.class = "empty") =>
       (lastInboundClose.kind = "accept" /\ lastInboundClose.code = 1000)
  /\ (lastInboundClose.class = "one_byte") =>
       (lastInboundClose.kind = "accept" /\ lastInboundClose.code = 1002)
  /\ (lastInboundClose.class = "valid_code_reason") =>
       (lastInboundClose.kind = "accept" /\ lastInboundClose.code = 1000)
  /\ (lastInboundClose.class = "code_1007_empty_reason") =>
       (lastInboundClose.kind = "invalid_data" /\ lastInboundClose.code = 1007)
  /\ (lastInboundClose.class = "reserved_or_invalid_code") =>
       (lastInboundClose.kind = "invalid_data" /\ lastInboundClose.code = 1002)
  /\ (lastInboundClose.class = "invalid_utf8_reason") =>
       (lastInboundClose.kind = "runtime_rejection")

\* The outbound queue respects its declared bound. The cfg sets
\* MaxSends > QueueCapacity so removing the enqueue guard is detectable.
\* FALSIFIED BY: defect.model.unbounded-enqueue -- remove SendData's
\*   Len(outQ) < QueueCapacity guard.
QueueNeverExceedsCapacity == Len(outQ) <= QueueCapacity

\* A pending process-stage rejection can only exist while OPEN and only
\* after the truncated frame was actually recorded at translate stage -- the
\* two stages cannot collapse into an unrecorded reject. It can only exist
\* while OPEN because every action that begins or completes a close discards
\* it, mirroring Java: once CLOSING, the tail's process-stage
\* InvalidDataException reaches close(e), which early-returns
\* (WebSocketImpl.java:463-464), so a staged rejection can never govern a
\* close outcome (review round 1, BLOCKING-1: the pre-fix model reached
\* Closing with pendingProcessReject = TRUE via Init -> OpenHandshake ->
\* RecvTextTruncatedTail -> LocalCloseValid).
\* FALSIFIED BY: defect.model.truncated-tail-single-stage -- in
\*   RecvTextTruncatedTail replace inboundCount' = inboundCount + 1 with
\*   UNCHANGED inboundCount; and defect.model.truncated-tail-survives-close
\*   -- in LocalCloseValid replace pendingProcessReject' = FALSE with
\*   UNCHANGED pendingProcessReject (the exact reviewer trace above).
TruncatedTailStaging ==
  pendingProcessReject => (state = "Open" /\ inboundCount >= 1)

\* --------------------- checked temporal properties ------------------------
\* These are action/liveness properties and are declared honestly as
\* PROPERTY, never as INVARIANT.

\* CLOSED is absorbing (formal.close.terminal-absorbing).
\* JAVA: WebSocketImpl.java:531-533 closeConnection early-returns once
\*   CLOSED; no Java path leaves CLOSED.
\* FALSIFIED BY: defect.model.reopen-after-terminal -- add a Reopen action
\*   (state = "Closed" /\ state' = "Open" /\ UNCHANGED the rest) to Next.
TerminalAbsorbing == [][(state = "Closed") => (state' = "Closed")]_vars

\* Under the declared fairness, a closing connection eventually terminates.
\* FALSIFIED BY: defect.model.starved-closing-resolution -- change the cfg
\*   SPECIFICATION from FairSpec to Spec; TLC then finds the lasso that
\*   stutters in CLOSING forever.
ClosingLeadsToClosed == (state = "Closing") ~> (state = "Closed")

====
