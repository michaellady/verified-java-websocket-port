\* US-006 abstract connection lifecycle model for the verified Java-WebSocket
\* port (Claude plane). Authority: the pinned quarantined Java-WebSocket 1.6.0
\* tree at .quarantine/Java-WebSocket-da3cf2a777aed862f2f5b5cf060cae7969958667/
\* src/main/java/org/java_websocket/ (all \* JAVA: citations below are
\* package-root-relative file:line references into that tree, each verified by
\* direct read), carrying the US-005 live-calibrated close-code semantics
\* (evidence/corpus-calibration.json, status LIVE_CALIBRATED: the
\* jm-close-code-1000 Java behavioral mutant was killed 71 times -- 19+26+26
\* across tiers -- against the predicted JAVA_INVALID_DATA close-code
\* signature, live-confirming the CloseFrame normalization table modeled here,
\* including empty-payload-close normalizing to 1000, not 1005).
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
\* Java interleavings (send-vs-close, reset-vs-decode, timer-vs-worker) are
\* deliberately NOT modeled here; they are classified as not-corpus-encodable
\* in assurance/concurrency/plan.json and the port serializes them by
\* construction. Two deliberate abstractions widen the model relative to Java:
\* (1) the translate-stage and process-stage of truncated-tail text rejection
\* are split into two atomic actions although Java performs both inside one
\* decodeFrames call, and (2) the outbound queue is finitely bounded via
\* QueueCapacity although Java's outQueue is unbounded -- a recorded
\* divergence pointer, see behavior_delta_ledger in
\* assurance/concurrency/plan.json. Both widenings only ADD behaviors or
\* bound counters; neither hides a modeled transition.
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
  terminalDeliveries,   \* onWebsocketClose deliveries observed (exactly-once obligation)
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
\* are the live-confirmed normalization outcomes.
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
\*   1000 (NORMAL, line 250-251; the jm-close-code-1000-confirmed path), one
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
\* recorded-then-rejected ordering (a sound widening, see MODEL SCOPE).
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
\*   1000, live-confirmed by the jm-close-code-1000 mutant kills)
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
  /\ UNCHANGED <<sendCount, terminalDeliveries, pendingProcessReject,
                 droppedWrites, rejectedLocalCloses>>

\* Inbound close frame rejected by CloseFrame.isValid: the
\* InvalidDataException carries 1007 (NO_UTF8 code with empty reason) or 1002
\* (reserved/invalid codes), and the error-close path emits a close frame
\* with that code and enters CLOSING.
\* JAVA: framing/CloseFrame.java:226-243 the isValid rejection chain
\* JAVA: drafts/Draft_6455.java:595 frame.isValid() at translate time
\* JAVA: WebSocketImpl.java:391-418 decodeFrames catch -> close(e) at 405-408
\* JAVA: WebSocketImpl.java:463-507 close() -> CLOSING at 503
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
  /\ UNCHANGED <<sendCount, terminalDeliveries, pendingProcessReject,
                 droppedWrites, rejectedLocalCloses>>

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
LocalCloseValid ==
  /\ state = "Open"
  /\ Len(outQ) < QueueCapacity
  /\ closeDetail' = [origin |-> "local", code |-> 1000]
  /\ outQ' = Append(outQ, "close")
  /\ state' = "Closing"
  /\ UNCHANGED <<sendCount, inboundCount, terminalDeliveries,
                 lastInboundClose, pendingProcessReject, droppedWrites,
                 rejectedLocalCloses>>

\* Local close with a code CloseFrame.isValid rejects (for example 1015,
\* which setCode first normalizes to 1005 and isValid then rejects): the
\* generated frame is invalid, no close frame is sent, and Java falls back to
\* flushAndClose(ABNORMAL_CLOSE=1006) before entering CLOSING.
\* JAVA: framing/CloseFrame.java:179-184 setCode: TLS_ERROR 1015 -> NOCODE
\* JAVA: framing/CloseFrame.java:226-243 isValid rejects NOCODE and friends
\* JAVA: WebSocketImpl.java:488-492 catch InvalidDataException ->
\*   flushAndClose(CloseFrame.ABNORMAL_CLOSE, "generated frame is invalid")
\* JAVA: WebSocketImpl.java:503 readyState = CLOSING
LocalCloseInvalidCode ==
  /\ state = "Open"
  /\ rejectedLocalCloses < 1
  /\ rejectedLocalCloses' = rejectedLocalCloses + 1
  /\ closeDetail' = [origin |-> "error", code |-> 1006]
  /\ state' = "Closing"
  /\ UNCHANGED <<outQ, sendCount, inboundCount, terminalDeliveries,
                 lastInboundClose, pendingProcessReject, droppedWrites>>

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
\* onWebsocketClose exactly once, and reaches CLOSED. Writes still queued at
\* key-cancel are dropped.
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
\* JAVA: WebSocketImpl.java:530-567 terminal transition, exactly-once
\*   onWebsocketClose at 557, CLOSED at 566
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

\* The terminal event is delivered at most once (US-017 AC2's model-level
\* obligation; Java enforces it through the L2 monitor's CLOSED check).
\* terminalDeliveries deliberately ranges over 0..2 in TypeInvariant so the
\* double-delivery state is representable and this invariant is falsifiable.
\* FALSIFIED BY: defect.model.double-terminal-delivery -- add "Closed" to
\*   TransportEOF's enabling state set; TLC then reaches
\*   terminalDeliveries = 2.
TerminalDeliveredAtMostOnce == terminalDeliveries <= 1

\* Every closed connection delivered its terminal event exactly once
\* (formal.connection.no-terminal-escape: no path reaches CLOSED without the
\* exactly-once onWebsocketClose at WebSocketImpl.java:557).
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

\* The live-confirmed CloseFrame normalization table (the jm-close-code-1000
\* kill signature): this invariant restates the table independently of the
\* receive actions, so a mis-normalization mutation on either side is caught.
\* FALSIFIED BY: defect.model.empty-close-misnormalized -- in
\*   RecvCloseAccept assign code 1002 for the "empty" class (the historical
\*   B1-style empty-close mis-normalization, caught live by the
\*   jm-close-code-1000 mutant's 71-kill signature).
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
\* two stages cannot collapse into an unrecorded reject.
\* FALSIFIED BY: defect.model.truncated-tail-single-stage -- in
\*   RecvTextTruncatedTail replace inboundCount' = inboundCount + 1 with
\*   UNCHANGED inboundCount.
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
