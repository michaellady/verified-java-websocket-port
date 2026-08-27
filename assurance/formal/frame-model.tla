\* US-012 abstract framing model (AC5) for the verified Java-WebSocket port
\* (Claude plane). This model abstracts the SHIPPED PORT decoder --
\* ws_core::framing::Draft6455 (rust/ws-core/src/framing.rs:
\* decode_frame_header, translate_single_frame, apply_mask) -- which is
\* itself Java-faithful, not RFC-idealized. The behavioral authority is the
\* pinned quarantined Java-WebSocket 1.6.0 tree at
\* .quarantine/Java-WebSocket-da3cf2a777aed862f2f5b5cf060cae7969958667/
\* src/main/java/org/java_websocket/ (all \* JAVA: citations below are
\* package-root-relative file:line references into that tree) via the
\* reference model internal/corpora/derive.go.
\*
\* STAGE AS: FrameModel.tla -- TLA+ module identifiers cannot contain a
\* hyphen, so a TLC run must stage this file as FrameModel.tla and
\* frame-model.cfg as FrameModel.cfg in a scratch directory:
\*   cp frame-model.tla FrameModel.tla
\*   cp frame-model.cfg FrameModel.cfg
\*   java -cp tla2tools.jar tlc2.TLC -config FrameModel.cfg FrameModel
\*
\* MODEL_CHECK: EXECUTED -- see assurance/formal/frame-results.json for the
\* executed record (attempt id, tool digest, banners, exit codes, state
\* counts, receipt digests). The results document is the authority; this
\* header is a pointer, not a second copy of the numbers.
\*
\* CLAIM CEILING: proved-model only, exactly as the US-006 connection model.
\* Checking this abstraction establishes NOTHING about the production Rust
\* decoder without a reviewed composition/refinement link. No proof-only
\* duplicate implementation exists or is permitted: this file is
\* specification language only.
\*
\* JAVA-FAITHFUL, NOT RFC-STRICT. The port deliberately does not implement
\* several RFC 6455 rejections because the pinned runtime does not. Each is
\* recorded in evidence/java/behavior-delta-ledger.json and is modeled here
\* by its ABSENCE from the rejection table, which the
\* VerdictMatchesDeclaredTable invariant pins mechanically:
\*   ledger sequence 17, delta-b80af180e23baf... (noncanonical-extended-
\*     length): the RFC requires rejecting non-minimal 16/64-bit length
\*     encodings with 1002; the pinned runtime performs no minimality check,
\*     so this model's marker and length-class dimensions are INDEPENDENT --
\*     an ext16 or ext64 frame carrying a length that would fit a shorter
\*     form decodes normally.
\*   ledger sequence 18, delta-d3c9c70db9d4a4... (mask-by-role-acceptance):
\*     the RFC requires rejecting role-inappropriate masking with 1002; the
\*     pinned runtime accepts either masking toward either role, so the
\*     masked flag never appears in the rejection table -- only in the
\*     consumed-offset arithmetic and the unmask step.
\*   ledger sequence 19, delta-119646e52a54bc... (length-64bit-high-bit):
\*     pinned Java's behavior is UNOBSERVED; the port parses the length as
\*     an unsigned value and lets it fail the ordinary frame-size gate. The
\*     model has no separate high-bit rejection for the same reason; the
\*     over_cap length class is the modeled representative of that path.
\*   ledger sequence 20, delta-b375f7126b944a... (post-payload-rejection-
\*     site): verdicts agree with the RFC, but Java's observable rejection
\*     SITE for reserved bits and non-final control frames is after the full
\*     frame is consumed. The model splits the header phase from the payload
\*     phase precisely so this site distinction is checked, not assumed.
\*   ledger sequence 21, delta-ecf707c2483b2d... (control-extended-length-
\*     marker-site): a control frame carrying an extended-length MARKER is
\*     rejected at header byte 2 WITHOUT reading the declared length.
\*   ledger sequence 22, delta-4e6bffb12b0585... (consumed-bytes-error-
\*     sites): the consumed-byte offsets are Java-specific observables, so
\*     they are modeled explicitly (2 / length site / full frame) rather
\*     than abstracted away.
\*   ledger sequence 24, delta-cc022411648aec... (buffer-limit-check-sites):
\*     cumulative buffer limits are checked at fragment starts and fins, not
\*     per append. Fragment reassembly is OUT OF SCOPE for this model (see
\*     MODEL SCOPE) and is named here only so its absence is deliberate.
\*
\* A REAL FINDING RECORDED, NOT SUPPRESSED. The shipped port checks the
\* 125-octet control-payload limit twice: once by rejecting any control
\* frame whose length MARKER is >= 126 at header byte 2, and again by
\* comparing the decoded payload length against 125 at the length site. The
\* second comparison is UNREACHABLE, because a control frame that survives
\* the first gate has an inline marker and therefore a length of at most
\* 125. The invariant ControlOverLimitRejectedAtBaseHeader states this
\* mechanically: every over-limit control frame is rejected at consumed
\* offset 2, never at the length site. This is NOT a defect -- the shipped
\* Java gate has the same shape (drafts/Draft_6455.java:617-620 throws for
\* PING/PONG/CLOSING as soon as the >125 escape is entered, before the
\* extended length bytes are read) -- so the port's second comparison is
\* defensive depth, and the finding is recorded rather than "fixed".
\*
\* MODEL SCOPE. The model covers the US-012 obligations: canonical 7-/16-/
\* 64-bit length decoding, the header-time length gates, opcode
\* discrimination, control-frame constraints, the consumed-offset
\* observables, allocation bounded by the configured frame cap, and the
\* mask XOR equation and its involution. DELIBERATELY OUT OF SCOPE, each
\* owned by another artifact: close-payload semantics and the terminal
\* lifecycle (assurance/formal/close-model.tla), text UTF-8 two-stage
\* validation and fragment reassembly (US-013/US-014 corpora and
\* assurance/formal/connection-model.tla), and every concurrent
\* interleaving (assurance/concurrency/plan.json, which classifies the racy
\* seams as not-corpus-encodable; the port serializes them by construction).
\*
\* DECLARED ABSTRACTIONS, stated plainly.
\* RESTRICTIONS (behaviors the model HIDES):
\*   (1) MaxFrames bounds the decoded frame history; behaviors with longer
\*       histories do not exist in the model and nothing is claimed about
\*       them. Frames are decoded independently in the shipped decoder
\*       (translate_single_frame takes one complete span), so a bounded
\*       history loses no cross-frame coupling that this model claims.
\*   (2) Payload LENGTH is abstracted to four classes with concrete integer
\*       representatives (zero, within_control = ControlPayloadLimit,
\*       over_control = ControlPayloadLimit + 1, over_cap =
\*       FramePayloadCap + 1). Lengths strictly between the representatives
\*       are not enumerated; the gates are monotone comparisons against the
\*       two constants, so each class is exercised at its boundary.
\*   (3) The three reserved bits are abstracted to one boolean: the shipped
\*       check is a disjunction over the three bits with a single verdict
\*       (1002 at the full frame), so the abstraction is exact for the
\*       modeled property.
\*   (4) On the mask track each octet is abstracted to ByteModulus values.
\*       XOR acts independently per bit position, so the reduced byte
\*       domain is exact for the involution and key-index-alignment
\*       properties; the ASSUME below additionally checks the full two-bit
\*       XOR table exhaustively, wider than the track's own domain.
\* ADDITIONS (behaviors the model has that the shipped decoder does not):
\*   (5) The header phase and the payload phase are separate atomic actions
\*       although translate_single_frame performs both inside one call.
\*       Splitting them only ADDS schedules (a state where a header has been
\*       accepted and the payload not yet processed), which can make the
\*       checked invariants harder to satisfy, never easier.
\*   (6) The decode track and the mask track are disjoint: Init picks one
\*       and no action switches. They are two independent obligations
\*       carried by one module, so the state space is their SUM rather than
\*       their product. Nothing links them, and nothing is claimed about
\*       their interaction; the shipped coupling (an accepted masked frame's
\*       payload is unmasked in place) is asserted by neither track.

---- MODULE FrameModel ----
EXTENDS Integers, Sequences

\* Finite bounds. Every counter, sequence, and domain below is bounded
\* through these constants; the shipped frame-model.cfg assigns concrete
\* values, so the reachable state space is finite by construction.
\* FramePayloadCap mirrors the port's default max_frame_payload_bytes
\* (rust/ws-core/src/config.rs LimitField::MaxFramePayloadBytes = 65536) and
\* ControlPayloadLimit is Java's fixed 125.
CONSTANTS MaxFrames, ControlPayloadLimit, FramePayloadCap, ByteModulus, MaxPayloadOctets

ASSUME MaxFrames \in Nat /\ MaxFrames >= 1
ASSUME ControlPayloadLimit \in Nat /\ ControlPayloadLimit >= 1
ASSUME FramePayloadCap \in Nat /\ FramePayloadCap > ControlPayloadLimit
ASSUME ByteModulus \in Nat /\ ByteModulus >= 2
ASSUME MaxPayloadOctets \in Nat /\ MaxPayloadOctets >= 1

VARIABLES
  track,            \* "decode" or "mask": the disjoint obligation tracks
  phase,            \* decoder pipeline stage / mask pipeline stage
  frame,            \* the wire frame descriptor under decode
  verdict,          \* the decoder's outcome for that frame
  framesDone,       \* bounded count of retired frames
  allocated,        \* octets the decoder reserved for the last payload
  wirePayload,      \* masked octets as they arrived on the wire
  semanticPayload,  \* octets after the decode-side unmask
  maskKey           \* the four-octet mask key

vars == <<track, phase, frame, verdict, framesDone, allocated,
          wirePayload, semanticPayload, maskKey>>

Tracks == {"decode", "mask"}
Phases == {"idle", "header", "payload", "done", "masked", "unmasked"}
Opcodes == {"data", "control", "unknown"}
Markers == {"inline", "ext16", "ext64"}
LengthClasses == {"zero", "within_control", "over_control", "over_cap"}
FrameCloseCodes == {0, 1002, 1009}
ByteValues == 0..(ByteModulus - 1)

\* Wire frame descriptors. The well-formedness conjunct is the wire grammar,
\* not a validity check: the inline 7-bit marker field can only express
\* lengths up to ControlPayloadLimit, so the larger classes require an
\* extended marker. Marker and length are otherwise INDEPENDENT -- that
\* independence is what makes non-minimal encodings representable, which is
\* the point of ledger sequence 17.
WireFrames ==
  {f \in [opcode : Opcodes, marker : Markers, length : LengthClasses,
          masked : BOOLEAN, fin : BOOLEAN, rsv : BOOLEAN] :
     (f.marker = "inline") => (f.length \in {"zero", "within_control"})}

NoWireFrame ==
  [opcode |-> "data", marker |-> "inline", length |-> "zero",
   masked |-> FALSE, fin |-> TRUE, rsv |-> FALSE]

NoVerdict == [status |-> "none", code |-> 0, consumed |-> 0]
Accepted == [status |-> "accepted", code |-> 0, consumed |-> 0]
Reject(code, consumed) ==
  [status |-> "rejected", code |-> code, consumed |-> consumed]

IsControl(f) == f.opcode = "control"

\* Concrete integer representative of each length class (restriction 2).
LengthOctets(class) ==
  CASE class = "zero" -> 0
    [] class = "within_control" -> ControlPayloadLimit
    [] class = "over_control" -> ControlPayloadLimit + 1
    [] class = "over_cap" -> FramePayloadCap + 1

\* The consumed offset at which the declared length becomes known: 2 for the
\* inline marker, 4 after the 16-bit escape, 10 after the 64-bit escape.
LengthSite(f) ==
  CASE f.marker = "inline" -> 2
    [] f.marker = "ext16" -> 4
    [] f.marker = "ext64" -> 10

HeaderOctets(f) == LengthSite(f) + (IF f.masked THEN 4 ELSE 0)
FrameOctets(f) == HeaderOctets(f) + LengthOctets(f.length)
MaxFrameOctets == 14 + FramePayloadCap + 1

\* ---- the rejection table, stated once as a pure function ------------------
\* HeaderRejection and PostPayloadRejection are the two halves of the shipped
\* decoder's check order. The actions below re-derive the same outcomes
\* through the pipeline; the VerdictMatchesDeclaredTable invariant restates
\* the whole table, so a mutation on either side is caught by TLC rather
\* than being true by construction (the duplication is deliberate, matching
\* the connection model's InboundCloseNormalization idiom).
\* JAVA: drafts/Draft_6455.java:886-889 toOpcode: an unknown opcode nibble
\*   throws InvalidFrameException, observable after the two base header
\*   bytes.
\* JAVA: drafts/Draft_6455.java:617-620 translateSingleFramePayloadLength:
\*   PING/PONG/CLOSING entering the >125 escape throw immediately, before
\*   the extended length bytes are read (ledger sequence 21).
\* JAVA: drafts/Draft_6455.java:648-663 translateSingleFrameCheckLengthLimit:
\*   a declared length above maxFrameSize throws LimitExceededException,
\*   which the port projects as close code 1009.
HeaderRejection(f) ==
  IF f.opcode = "unknown"
  THEN Reject(1002, 2)
  ELSE IF IsControl(f) /\ f.marker # "inline"
  THEN Reject(1002, 2)
  ELSE IF IsControl(f) /\ LengthOctets(f.length) > ControlPayloadLimit
  THEN Reject(1002, LengthSite(f))
  ELSE IF LengthOctets(f.length) > FramePayloadCap
  THEN Reject(1009, LengthSite(f))
  ELSE Accepted

\* JAVA: drafts/Draft_6455.java:585-596 translateSingleFrame post-payload
\*   validity: the extension frame check (reserved bits, isFrameValid at
\*   588) and the frame's own isValid (595) run only after the payload has
\*   been read, so the observable consumed offset is the whole frame
\*   (ledger sequence 20).
\* JAVA: framing/ControlFrame.java:46-51 isValid: a control frame without
\*   FIN is invalid; the port reports 1002 at the full frame.
PostPayloadRejection(f) ==
  IF f.rsv
  THEN Reject(1002, FrameOctets(f))
  ELSE IF IsControl(f) /\ ~f.fin
  THEN Reject(1002, FrameOctets(f))
  ELSE Accepted

DeclaredVerdict(f) ==
  IF HeaderRejection(f) # Accepted
  THEN HeaderRejection(f)
  ELSE PostPayloadRejection(f)

\* ---- the mask equation ----------------------------------------------------
\* Bitwise XOR over the two-bit value domain, defined arithmetically because
\* TLA+ has no primitive XOR. Used for both the wire domain (ByteValues) and
\* the exhaustive ASSUME below.
Xor2(a, b) ==
  LET low == IF (a % 2) = (b % 2) THEN 0 ELSE 1
      high == IF ((a \div 2) % 2) = ((b \div 2) % 2) THEN 0 ELSE 1
  IN low + 2 * high

\* Exhaustive, checked ONCE by TLC at startup over the full two-bit domain
\* (wider than ByteValues when ByteModulus is 2): XOR with any key is an
\* involution. TLC reports "Assumption ... is false" if this fails.
ASSUME \A a \in 0..3 : \A b \in 0..3 : Xor2(Xor2(a, b), b) = a

WirePayloads == UNION {[1..n -> ByteValues] : n \in 0..MaxPayloadOctets}
MaskKeys == [1..4 -> ByteValues]

\* The repeating four-byte XOR: octet i is masked with key octet
\* 1 + ((i - 1) % 4). Applied on encode for the client role and removed on
\* decode; the same function serves both directions, which is what makes the
\* round trip an involution.
MaskApply(payload, key) ==
  [i \in DOMAIN payload |-> Xor2(payload[i], key[1 + ((i - 1) % 4)])]

\* ---- initial state --------------------------------------------------------
Init ==
  /\ track \in Tracks
  /\ phase = "idle"
  /\ frame = NoWireFrame
  /\ verdict = NoVerdict
  /\ framesDone = 0
  /\ allocated = 0
  /\ wirePayload = <<>>
  /\ semanticPayload = <<>>
  /\ maskKey = <<0, 0, 0, 0>>

\* ---- decode track ---------------------------------------------------------
\* One complete wire frame arrives for translation. The port's caller hands
\* translate_single_frame exactly one complete span produced by the length
\* grammar scan, so a frame either arrives whole or is not yet a frame.
\* JAVA: drafts/Draft_6455.java:759-771 translateFrame: a span that is not
\*   yet complete raises IncompleteException and is stashed for the next
\*   read, so only complete frames reach translateSingleFrame.
StartFrame(f) ==
  /\ track = "decode"
  /\ phase = "idle"
  /\ framesDone < MaxFrames
  /\ frame' = f
  /\ verdict' = NoVerdict
  /\ allocated' = 0
  /\ phase' = "header"
  /\ UNCHANGED <<track, framesDone, wirePayload, semanticPayload, maskKey>>

\* Header-time rejection: unknown opcode, an extended-length marker on a
\* control frame, an over-limit control payload, or a declared length above
\* the configured cap. No payload has been allocated at this point -- that
\* ordering is the whole point of the header-time length gate.
\* JAVA: drafts/Draft_6455.java:528-566 translateSingleFrame: the header is
\*   decoded and translateSingleFrameCheckLengthLimit runs BEFORE the
\*   ByteBuffer.allocate at 557.
HeaderReject ==
  /\ track = "decode"
  /\ phase = "header"
  /\ HeaderRejection(frame) # Accepted
  /\ verdict' = HeaderRejection(frame)
  /\ phase' = "done"
  /\ UNCHANGED <<track, frame, framesDone, allocated, wirePayload,
                 semanticPayload, maskKey>>

\* Header accepted: exactly the declared payload length is reserved. The
\* shipped port reserves with_capacity(payload_len) after the same gates.
\* JAVA: drafts/Draft_6455.java:555-563 the checkAlloc-guarded payload
\*   allocation and the in-place unmask loop over the four-byte key.
\* JAVA: drafts/Draft.java:322-327 checkAlloc: a negative byte count throws
\*   InvalidDataException(PROTOCOL_ERROR); the port's unsigned length plus
\*   the header-time gate makes the negative case unrepresentable.
HeaderAccept ==
  /\ track = "decode"
  /\ phase = "header"
  /\ HeaderRejection(frame) = Accepted
  /\ allocated' = LengthOctets(frame.length)
  /\ phase' = "payload"
  /\ UNCHANGED <<track, frame, verdict, framesDone, wirePayload,
                 semanticPayload, maskKey>>

\* Post-payload rejection with the full frame consumed (ledger sequence 20).
\* JAVA: drafts/Draft_6455.java:585-596 the post-payload validity block.
PostPayloadReject ==
  /\ track = "decode"
  /\ phase = "payload"
  /\ PostPayloadRejection(frame) # Accepted
  /\ verdict' = PostPayloadRejection(frame)
  /\ phase' = "done"
  /\ UNCHANGED <<track, frame, framesDone, allocated, wirePayload,
                 semanticPayload, maskKey>>

\* The frame is accepted and handed to the process stage.
\* JAVA: drafts/Draft_6455.java:892-900 processFrame: an accepted frame is
\*   dispatched by opcode.
PostPayloadAccept ==
  /\ track = "decode"
  /\ phase = "payload"
  /\ PostPayloadRejection(frame) = Accepted
  /\ verdict' = Accepted
  /\ phase' = "done"
  /\ UNCHANGED <<track, frame, framesDone, allocated, wirePayload,
                 semanticPayload, maskKey>>

\* The frame leaves the pipeline; its descriptor, verdict, and allocation
\* are retained as the last-frame observation the invariants read.
\* JAVA: drafts/Draft_6455.java:759-763 translateFrame loops to the next
\*   complete frame in the same read.
RetireFrame ==
  /\ track = "decode"
  /\ phase = "done"
  /\ framesDone' = framesDone + 1
  /\ phase' = "idle"
  /\ UNCHANGED <<track, frame, verdict, allocated, wirePayload,
                 semanticPayload, maskKey>>

\* Explicit terminal stuttering once the bounded frame budget is spent, so
\* the bound is not reported as a deadlock. TLC's deadlock detection stays
\* at its default (enabled).
\* JAVA: drafts/Draft_6455.java:764-770 translateFrame stops and stashes the
\*   remainder when no further complete frame is available.
DecodeIdle ==
  /\ track = "decode"
  /\ phase = "idle"
  /\ framesDone = MaxFrames
  /\ UNCHANGED vars

\* ---- mask track -----------------------------------------------------------
\* A masked frame's octets arrive on the wire together with the key.
\* JAVA: drafts/Draft_6455.java:558-560 the four-byte mask key is read from
\*   the buffer immediately before the unmask loop.
MaskSelect(p, k) ==
  /\ track = "mask"
  /\ phase = "idle"
  /\ wirePayload' = p
  /\ maskKey' = k
  /\ semanticPayload' = <<>>
  /\ phase' = "masked"
  /\ UNCHANGED <<track, frame, verdict, framesDone, allocated>>

\* The decode-side unmask: octet i XORed with key octet 1 + ((i - 1) % 4).
\* JAVA: drafts/Draft_6455.java:561-563 the decode unmask loop.
\* JAVA: drafts/Draft_6455.java:511-517 the encode mask loop uses the same
\*   equation, which is why the round trip is an involution.
MaskUnmask ==
  /\ track = "mask"
  /\ phase = "masked"
  /\ semanticPayload' = MaskApply(wirePayload, maskKey)
  /\ phase' = "unmasked"
  /\ UNCHANGED <<track, frame, verdict, framesDone, allocated, wirePayload,
                 maskKey>>

\* Terminal stuttering for the mask track.
\* JAVA: drafts/Draft_6455.java:574-575 the payload buffer is flipped and
\*   set on the frame; no further masking occurs.
MaskIdle ==
  /\ track = "mask"
  /\ phase = "unmasked"
  /\ UNCHANGED vars

Next ==
  \/ \E f \in WireFrames : StartFrame(f)
  \/ HeaderReject
  \/ HeaderAccept
  \/ PostPayloadReject
  \/ PostPayloadAccept
  \/ RetireFrame
  \/ DecodeIdle
  \/ \E p \in WirePayloads : \E k \in MaskKeys : MaskSelect(p, k)
  \/ MaskUnmask
  \/ MaskIdle

Spec == Init /\ [][Next]_vars

\* Fairness is deliberately narrow: only the in-flight resolution steps are
\* weakly fair. Frame ARRIVAL carries no fairness -- the decoder cannot
\* compel a peer to send, exactly as the connection model gives producer
\* actions no fairness.
ResolveFrame ==
  /\ phase \in {"header", "payload", "masked"}
  /\ (HeaderReject \/ HeaderAccept \/ PostPayloadReject \/ PostPayloadAccept
        \/ MaskUnmask)

FairSpec == Spec /\ WF_vars(ResolveFrame)

\* ------------------------- checked state invariants -----------------------
\* Every invariant below is a genuine state predicate: no primed variables,
\* no temporal operators. Each carries a FALSIFIED BY note naming the
\* representable mutation that makes TLC report a violation.

\* FALSIFIED BY: defect.frame.type-domain-escape -- change Init's verdict to
\*   [status |-> "none", code |-> 1007, consumed |-> 0]; 1007 is outside
\*   FrameCloseCodes.
TypeInvariant ==
  /\ track \in Tracks
  /\ phase \in Phases
  /\ frame \in WireFrames
  /\ verdict.status \in {"none", "accepted", "rejected"}
  /\ verdict.code \in FrameCloseCodes
  /\ verdict.consumed \in Nat
  /\ verdict.consumed <= MaxFrameOctets
  /\ framesDone \in 0..MaxFrames
  /\ allocated \in Nat
  /\ wirePayload \in WirePayloads
  /\ semanticPayload \in WirePayloads
  /\ maskKey \in MaskKeys

\* The two tracks are disjoint by construction; stating it as an invariant
\* makes the declared model structure machine-checked rather than asserted
\* in prose (declared abstraction 6).
\* FALSIFIED BY: defect.frame.track-leak -- drop the track = "decode"
\*   conjunct from HeaderAccept, letting a mask-track state enter the
\*   decoder pipeline.
TracksAreDisjoint ==
  /\ (track = "decode") => (phase \in {"idle", "header", "payload", "done"})
  /\ (track = "mask") => /\ phase \in {"idle", "masked", "unmasked"}
                         /\ frame = NoWireFrame
                         /\ verdict = NoVerdict
                         /\ framesDone = 0
                         /\ allocated = 0

\* The decoder's outcome is exactly the declared Java-faithful table -- no
\* extra rejection and no missing one. This is the invariant that pins the
\* ledger's non-rejections (sequences 17, 18, 19): adding an RFC-strict
\* minimality, role-masking, or high-bit rejection to any action makes TLC
\* report a violation immediately.
\* FALSIFIED BY: defect.frame.rfc-strict-noncanonical-length -- add
\*   "IF f.marker = \"ext16\" /\\ LengthOctets(f.length) <= 125 THEN
\*   Reject(1002, 4)" to the HeaderReject action without adding it to
\*   HeaderRejection; TLC then reaches a state whose verdict differs from
\*   DeclaredVerdict(frame).
VerdictMatchesDeclaredTable ==
  (verdict.status # "none") => (verdict = DeclaredVerdict(frame))

\* No allocation is ever larger than the configured frame cap, and no
\* allocation happens for a frame the header gate rejected. Together these
\* are the "no unbounded allocation" obligation: the reservation is made
\* only after the gate and only at the gated size.
\* FALSIFIED BY: defect.frame.allocate-before-gate -- move the
\*   allocated' assignment from HeaderAccept into StartFrame
\*   (allocated' = LengthOctets(f.length)); an over_cap frame then reserves
\*   FramePayloadCap + 1.
AllocationRespectsHeaderGate ==
  /\ allocated <= FramePayloadCap
  /\ (allocated > 0) => (HeaderRejection(frame) = Accepted)
  /\ (phase = "header") => (allocated = 0)

\* Over-cap lengths are rejected with 1009 at the length site -- before any
\* payload is read, which is what makes the gate a bound on allocation
\* rather than a late failure.
\* FALSIFIED BY: defect.frame.late-length-gate -- in HeaderRejection change
\*   the over-cap arm to Reject(1009, FrameOctets(f)).
OverCapRejectedAtLengthSite ==
  (verdict.status = "rejected" /\ verdict.code = 1009)
    => /\ LengthOctets(frame.length) > FramePayloadCap
       /\ verdict.consumed = LengthSite(frame)

\* An unknown opcode is rejected with 1002 after exactly the two base header
\* bytes (ledger sequence 22: the consumed offsets are Java observables).
\* FALSIFIED BY: defect.frame.unknown-opcode-late-site -- in
\*   HeaderRejection change the unknown-opcode arm to
\*   Reject(1002, FrameOctets(f)).
UnknownOpcodeRejectedAtBaseHeader ==
  (verdict.status = "rejected" /\ frame.opcode = "unknown")
    => (verdict.code = 1002 /\ verdict.consumed = 2)

\* THE RECORDED FINDING (see the header): every control frame whose declared
\* length exceeds the 125-octet limit is rejected at consumed offset 2 by
\* the extended-marker gate, so the shipped port's second comparison of the
\* decoded length against 125 is unreachable defensive depth. If this
\* invariant ever fails, the marker gate has been weakened and the finding
\* must be re-examined.
\* FALSIFIED BY: defect.frame.control-extended-marker-allowed -- delete the
\*   "IsControl(f) /\\ f.marker # \"inline\"" arm from HeaderRejection; the
\*   over-limit control frame is then rejected at the length site (4 or 10)
\*   instead of 2.
ControlOverLimitRejectedAtBaseHeader ==
  (verdict.status = "rejected" /\ IsControl(frame)
     /\ LengthOctets(frame.length) > ControlPayloadLimit)
    => (verdict.consumed = 2)

\* Every accepted control frame carries at most 125 octets and is final.
\* FALSIFIED BY: defect.frame.control-fin-not-checked -- delete the
\*   control-fin arm from PostPayloadRejection.
AcceptedControlFramesAreBounded ==
  (verdict.status = "accepted" /\ IsControl(frame))
    => /\ LengthOctets(frame.length) <= ControlPayloadLimit
       /\ frame.fin
       /\ frame.marker = "inline"

\* No rejection ever reports a consumed offset beyond the frame it was
\* decoding, and every rejection reports one of the three declared sites.
\* FALSIFIED BY: defect.frame.consumed-overrun -- in PostPayloadRejection
\*   change the reserved-bit arm to Reject(1002, FrameOctets(f) + 1).
ConsumedSiteIsDeclared ==
  (verdict.status = "rejected")
    => /\ verdict.consumed \in {2, LengthSite(frame), FrameOctets(frame)}
       /\ verdict.consumed <= FrameOctets(frame)

\* The mask round trip on the wire domain: unmasking recovers the semantic
\* octets, re-masking recovers the wire octets, and the length is preserved.
\* This is the state-level companion of the exhaustive ASSUME above.
\* FALSIFIED BY: defect.frame.mask-index-misalignment -- in MaskApply change
\*   the key index to 1 + (i % 4); TLC then reaches an unmasked state whose
\*   re-mask differs from the wire payload.
MaskRoundTrip ==
  (phase = "unmasked")
    => /\ semanticPayload = MaskApply(wirePayload, maskKey)
       /\ MaskApply(semanticPayload, maskKey) = wirePayload
       /\ Len(semanticPayload) = Len(wirePayload)

\* --------------------- checked temporal properties ------------------------
\* These are action and liveness properties and are declared honestly as
\* PROPERTY, never as INVARIANT.

\* The retired-frame counter never runs backwards: the decoder makes
\* monotone progress through the bounded frame budget.
\* JAVA: drafts/Draft_6455.java:759-763 translateFrame appends each decoded
\*   frame to the result list and advances the buffer; no path un-decodes a
\*   frame already handed to the caller.
\* FALSIFIED BY: defect.frame.budget-reset -- add a Reset action
\*   (phase = "idle" /\\ framesDone' = 0 /\\ UNCHANGED the rest) to Next.
FrameBudgetMonotone == [][framesDone' >= framesDone]_vars

\* Under the declared fairness, a frame that entered the pipeline always
\* reaches a verdict; the decoder never parks with a half-decoded frame.
\* FALSIFIED BY: defect.frame.starved-resolution -- change the cfg
\*   SPECIFICATION from FairSpec to Spec; TLC then finds the lasso that
\*   stutters in the header phase forever.
FramesAlwaysResolve == (phase \in {"header", "payload"}) ~> (phase = "done")

====
