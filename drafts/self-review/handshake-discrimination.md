# Handshake discrimination — raising the exam's ceiling

Branch `claude/handshake-discrimination`, from mainline `4a2b9c6`.

**Headline (MEASURED by the audit's own machinery, never asserted):** the 49-case
handshake exam produced **26** distinct scored observations; it now produces
**29**. Cases sharing an observation fall 27 → 23; the largest equivalence class
falls 11 → 10. The exam still scores 49/49 on both arms with the same 16
documented divergences — **and 49/49 still means at most 29 distinguishable
answers, not 49.**

The claim grade is unchanged: **BOUNDED**. Nothing here proves the surface
enumeration complete, and nothing here should be read as one.

---

## 1. What the 11-case class actually differs in

Driving the 49 committed cases through the harness and grouping the answers by
canonical JSON with the three identity fields stripped (the audit's own
`MeasureTranscript`) gave four classes of size > 1 and 22 singletons:

| size | observation | cases |
|---|---|---|
| 22 | `accept` + a distinct `sec_websocket_accept` | the 22 server-side accepts |
| 11 | `reject` / `invalid_handshake` / `close_code` 1002 | 0009 0010 0011 0012 0018 0031 0032 0033 0035 0036 0037 |
| 9 | `reject` / `not_matched` / `close_code` 1002 | 0023 0024 0025 0026 0028 0038 0039 0040 0041 |
| 4 | `incomplete` | 0042 0043 0044 0045 |
| 3 | `accept` with NO accept value | 0006 0007 0008 |

22 + 4 = 26. **Every bit of discriminating power the exam had beyond four
buckets was carried by one key, `sec_websocket_accept`, on one side.**

The 11-case class spans **seven corpus families and both directions**:

| case | direction | family | input |
|---|---|---|---|
| 0009 | client_request | method-not-get | `POST /socket/… HTTP/1.1` |
| 0010 | client_request | method-not-get | `PATCH /socket/… HTTP/1.1` |
| 0011 | client_request | http-version | `GET … HTTP/1.0` |
| 0012 | client_request | http-version | `GET … HTTP/0.9` |
| 0018 | client_request | missing-key | valid GET, no `Sec-WebSocket-Key` |
| 0031 | client_request | malformed-request-line | `GET/socket/…HTTP/1.1` (no SP) |
| 0032 | client_request | malformed-request-line | `GET … HTTP/1.1 EXTRA` |
| 0033 | client_request | obs-fold | folded continuation line |
| 0035 | server_response | status-not-101 | `HTTP/1.1 200 OK` |
| 0036 | server_response | status-not-101 | `HTTP/1.1 404 Not Found` |
| 0037 | server_response | status-not-101 | `HTTP/1.1 301 Moved Permanently` |

A **client** rejecting a 404 response and a **server** rejecting a POST upgrade
were the same scored row.

### What genuinely differs, checked against the pinned source

The pinned Java-WebSocket source was materialised in this container (see §7 for
what that materialisation is and is not worth). Reading it:

- **`Draft.java:101`** `IncompleteHandshakeException`; **`:106`** token-count
  `InvalidHandshakeException`; **`:117`** `"not an http header"`; **`:145`/`:149`**
  server method / HTTP version; **`:168`/`:172`** client status / HTTP version —
  every one of these is inside `translateHandshakeHttp`.
- **`Draft_6455.java:262-286`** `acceptHandshakeAsServer` and **`:306-343`**
  `acceptHandshakeAsClient` return `HandshakeState.NOT_MATCHED`.
- **`Draft_6455.java:438-440`** `postProcessHandshakeResponseAsServer` throws
  `InvalidHandshakeException("missing Sec-WebSocket-Key")`.
- **`WebSocketImpl.java:284-301`**: `acceptHandshakeAsServer` is called at :284;
  the application's `onWebsocketHandshakeReceivedAsServer` at **:289**;
  `postProcessHandshakeResponseAsServer` at **:301**.

So `invalid_handshake` conflates two structurally different events. For 0009-0012
and 0031-0037 the head never became a `Handshakedata` and **the application
listener was never reached**. For **0018 the listener ran** — the draft accepted
the handshake and only response construction failed. That is a real runtime fact
at the same tier `reject_channel` already reports (which draft-API call decided),
one call finer.

### What is legitimately unobservable, and why

- **Why a rejection happened within one stage.** `POST` vs `HTTP/1.0` vs a
  colon-less header line differ only in the `InvalidHandshakeException` *message
  string*. The differential already classifies detail strings non-semantic
  (`diffregress` `DetailField`), and reproducing Java's strings would be
  Java-quirk emulation — which by construction can never produce a
  Java-versus-Rust signal (the audit's own
  `AC5-JQ-STRUCTURAL-no-java-vs-rust-signal`). The corpus's `HS_*` reject codes
  are the *RFC model's* labels; the runtime does not produce them, so scoring
  them would score the Go model against itself.
- **The 200 / 404 / 301 status codes of 0035-0037.** Confirmed from source:
  `translateHandshakeHttpClient` throws on `!"101".equals(token)` **before**
  `setHttpStatus`/`setHttpStatusMessage` run. Java never records the status of a
  non-101 response. Not observable — not "not reported".
- **The 8 server-side rejections on the wire.** `closeConnectionDueToWrongHandshake`
  (`WebSocketImpl.java:426-429`) writes `generateHttpResponseDueToError(404)`,
  which is a **constant** string with no input-dependent content. The port's
  `REJECT_RESPONSE` is likewise constant. All eight are byte-identical to the peer.
- **The 4 `incomplete` cases (0, 4, 86, 171 octets).** Java buffers and writes
  nothing; the parse re-runs from scratch on the next chunk, so no partial state
  survives. `IncompleteHandshakeException.getPreferredSize()` is
  `buf.capacity() + 128` — a buffer-growth hint that is a function of the input
  length, not of the behaviour. NC-08's collision is **structural**.
- **The 9-case `not_matched` class.** Both `acceptHandshakeAsServer` and
  `acceptHandshakeAsClient` reach `return NOT_MATCHED` from several sites, but
  `HandshakeState` is **one enum value returned by one method**. There is no
  finer draft-API fact underneath it. Structural.

---

## 2. The honesty criterion, stated before it was applied

A key earns a place in the projection **iff its value is computed by the runtime
under test and could differ between two implementations answering the same
request**. A key that is a fixed function of the request bytes — a re-emitted
input field, a length — is an **echo**: it inflates the census by exactly zero
bits of differential power. That is the move the audit forbids, and it is the
easy way to make 49 distinct observations out of 49 rows.

**Recorded by name, distinctions considered and REJECTED under that criterion:**

- **`direction`.** A request echo. The project's own vocabulary already settles
  this: `behaviour.failure`'s `Drops` list calls `role` and `initial_state`
  "request echoes, recoverable from request_digest". Adding `direction` would
  have split the 11-class into 8 + 3 and the 9-class into 5 + 4 — +3 census for
  no differential power at all. **Not done.**
- The corpus `HS_*` reject codes (RFC-model labels the runtime does not produce).
- Java `InvalidHandshakeException` message strings (non-semantic; emulation).
- The parsed status code / status message of a rejected client response (Java
  never builds them; and derivable from the input regardless).
- Bytes consumed or `getPreferredSize()` on `incomplete` (input length).
- The request path, Host, and resource descriptor (echoes; already NC-07).
- **The 101 accept response head.** This one is a real, claimed-byte-exact
  artefact and NC-07 names its loss. It was left alone for two reasons, both
  worth stating: it would move the census by **zero** (all 22 server accepts are
  already distinct), and its `Date` field is a clock reading, so scoring the head
  would fail 22 cases against any live run. NC-07 stands, undiminished.
- **The constant 404 reject head.** Constant; zero information.

---

## 3. What was added, and what each key bought

### `reject_stage` — which draft-API call decided (+1 observation)

`translate` / `accept_predicate` / `response_build`. Emitted by **both** arms
(`ws_core::handshake::RejectStage`; `HandshakeEngine.serverSide`/`clientSide`),
compared **fail-closed** by `evaluateHandshakeLiveResponse`, with presence parity
in both directions.

On the Java side the three draft-API calls were moved into **separate try
blocks** so the reported stage is the call that actually produced the outcome
rather than a guess about which of three sites inside one `try` threw. Same
calls, same order, same observable/channel/close code.

Bought: **11 → 10 + 1**. It separates 0018 (the listener ran; response
construction failed) from the ten cases where the head never parsed. Measured
distribution, identical on both arms: `translate` 10, `accept_predicate` 9,
`response_build` 1, absent 29.

It bought nothing on the 9-case `not_matched` class, and could not have — §1.

### The client-side `sec_websocket_accept` (+2 observations)

The adapter emitted none, on the reading that "no accept value is observable on
the client side". What is true is that the client does not **send** one. It
**derives** one — `generateFinalKey(trim(key))`, `Draft_6455.java:318-325` — and
matching it literally is the entire client acceptance predicate. The Java adapter
now reads it back through the library's own `Handshakedata`, exactly as the
server side reads its value back out of the bytes it rendered; ws-core reports
the value its own derivation produced.

Bought: **3 → 3**, and it puts the client-side accept derivation directly under
the exam rather than leaving it inferable from the accept/reject pattern of
0006-0008 versus 0039-0040. **Stated plainly: the added differential power here
is modest** — a port with a broken client derivation would already have failed
0006-0008 by rejecting them. What changes is that the check is now direct.

**26 + 1 + 2 = 29.** Recomputed, never edited.

---

## 4. Effect on the confirmed collisions — run, not argued

`normcollidectl report`, exit **0**, harness digest recorded:

    NC-07 handshake.judged want=CONFIRMED got=CONFIRMED
    NC-08 handshake.judged want=CONFIRMED got=CONFIRMED
    NC-09 handshake.judged want=CONFIRMED got=CONFIRMED
    (NC-01..04 CONFIRMED, NC-10/NC-11 REFUTED as declared)

**No confirmed collision was refuted.** NC-09 is the one that had to be checked
rather than assumed: both its seeds omit `Sec-WebSocket-Version`, so both are
decided by `acceptHandshakeAsServer` returning `NOT_MATCHED` — same channel
**and** same stage. Its prose now says so, and says why the refinement could
never have separated them.

The `handshake_statement` was rewritten to stop claiming "a rejection reports
only a two-valued channel plus a constant close code", which the change made
false, and it now records the 26 → 29 history so the number reads as a
measurement rather than a target.

---

## 5. The exam's pass criterion — no case was lost

| arm | result | exit |
|---|---|---|
| port (`ws-oracle-harness`, runtime neutralised) | executed 49, passed 49, failed 0, **16 divergences** | 0 |
| live Java-WebSocket 1.6.0 (see §7) | executed 49, passed 49, failed 0, **16 divergences** | 0 |

The two arms' 49 rows are **byte-identical once `runtime` is excluded** — zero
differing rows, including on both new keys. The Java arm independently measures
**29** distinct scored observations, 23 sharing, largest class 10.

Nothing became a failure. There is no hard stop to report on this axis.

Both arms' `reject_stage` distributions are identical and were produced
independently — the port from `ws_core::handshake::RejectStage`, the Java arm
from which draft-API call actually threw or returned:

    translate 10   accept_predicate 9   response_build 1   absent 29

`response_build` occurs exactly once, on us005.hs.0018, **and the real
Java-WebSocket 1.6.0 library produced it**. That is the evidence that the stage
is a fact about the shipped runtime and not an artefact of the Go model.

`make -C rust gates`: **exit 0** (fmt-check, clippy, fixture-guard, test,
test-release, ac1-gates 8/8, ledger-gates including the handshake mapping
census, oracle-hierarchy-gates).

---

## 6. RED-first readings and deletion attacks

Every mutation used `false &&` or a `if false {}` arm; nothing was broken at
compile time, and every exit code below was read from the process.

| # | what was deleted | result | exit |
|---|---|---|---|
| 0a | *(none — baseline)* existing corpora suite run against the new model | **RED** `us005.hs.0006: server-response observable must not carry an accept value` | 1 |
| 0b | *(none — baseline)* existing harness protocol suite | **RED** `real_server_response_case_accepts_without_an_accept_value` | 1 |
| 1 | scorer's `reject_stage` equality comparison | **RED** `reject_stage drifted to "accept_predicate" must fail` | 1 |
| 2 | scorer's `unexpected reject_stage` presence check | **GREEN — SURVIVED** | 0 |
| 2′ | same, after adding the missing test | **RED** `accept carrying a reject_stage must not pass` | 1 |
| 3 | the client-side accept derivation in the Go model | **RED**, two tests | 1 |
| 4 | ws-core: 0018's stage forced to `translate` (end-to-end, through the exam) | **RED** `us005.hs.0018: reject_stage "translate", expected "response_build"`, 48/49 | 1 |
| 5 | ws-core: client accept value emptied (end-to-end) | **RED** 0006/0007/0008 fail, 46/49 | 1 |
| 6 | `handshake_adapter.rs::respond`'s `reject_stage` insertion, against the Rust suite alone | **GREEN — SURVIVED** (the exam did catch it: 20 failures, exit 1) | 0 |
| 6′ | same, after adding `rejections_name_the_draft_api_call_that_decided` | **RED** `crafted.oneword: expected stage translate` | 101 |

**Attacks 2 and 6 are the findings to keep — two survivors out of six.** In both
cases a check I had just written was GREEN when deleted. Green when deleted is
not evidence that a check works; it is evidence that it does not, and saying so
is the point of running the attack rather than reasoning about it.

Attack 6 is the more instructive of the two. The exam *did* catch it — 20 cases
failed, exit 1 — so the property was defended somewhere. But the Rust suite,
which is what a Rust-side change runs first, was entirely silent, and "some
other suite two layers away would have caught it" is not a test. The new test
covers all three stages including the two that share the `invalid_handshake`
channel, which is the collision the key exists to resolve.

Two survivors in a first honest sweep of two new keys is in line with the 11, 19
and 20 that earlier tracks found. It is not a reason to think the sweep is now
complete.

Attacks 0a and 0b are worth separating from the rest: those two REDs were not
mine to arrange. Two existing tests pinned the OLD absence of the client-side
accept value and caught the change unprompted. Both were replaced by **stronger**
pins (the value must equal the derivation; the whole response line is pinned
with it), never relaxed.

---

## 7. Environment regressions, and what they cost

- **`.quarantine/` is a self-referential symlink** (`.quarantine -> .quarantine`),
  so the pinned source tree is absent. The GitHub archive endpoint that the pin's
  `sha256` covers is proxy-refused, so **the archive digest in
  `evidence/intake/source-pins.json` was NOT verified.** What was verified is a
  *different* check, and it must not be reported as the same one: the pin's
  `provenance` field names `git commit da3cf2a777aed862f2f5b5cf060cae7969958667
  tree 30c108fd7b68663f645ee9cb8e3daaf4a39235ea`, and `git cat-file -p da3cf2a…`
  on a fresh upstream clone prints exactly that tree hash. The source was then
  materialised with `git archive da3cf2a… | tar -x`. Tree-hash provenance, not
  archive-digest provenance.
- **The pinned JDK 17.0.19 is gone and unobtainable.** The live Java run in §5
  used **OpenJDK 21.0.10**. It is therefore **NOT a pinned-baseline reading** and
  must not be cited as one. What it does establish is strong and worth having:
  the real Java-WebSocket 1.6.0 jar (fetched from Maven Central, sha256
  `eae29213…c22f`, matching the accepted-runtime pin exactly) produces
  `reject_stage` `response_build` for us005.hs.0018 and `translate` for the other
  ten — so the stage is a fact about the shipped library, not an invention of the
  Go model. `--release 17` compilation, so the bytecode target is the pinned one
  even though the running JVM is not.
- **Baseline failure not named in the handoff:** `internal/formalcoverage` and
  `cmd/formalcoverctl` fail on
  `websocket_driver::ConnectionOwner::poll/NEAREST_DECLARATION_IS_AT_THE_LINE_IT_CITES`
  — a citation into `rust/ws-driver/src/lib.rs:756`. Not argued: mainline 4a2b9c6
  was materialised into a separate tree with `git archive` and the same two
  packages were run there. **Both FAIL on clean mainline**; `internal/linkage`
  and `internal/oraclerank` pass there (`-count=1`, no cache). The handoff named
  `internal/lab`, `internal/portplan` and `internal/formalplan`; this is a
  fourth and fifth.
- `internal/formalplan`'s failures in this container are the `.quarantine`
  regression surfacing directly:
  `QUARANTINE_UNWRITABLE: mkdir ../../.quarantine: file exists`.

## 7a. Records this change legitimately invalidated, and how each was refrozen

Three digest bindings refused after the change. Each refusal was correct, each
was regenerated through its own sanctioned path, and none was edited by hand:

| record | what refused | path taken |
|---|---|---|
| `evidence/normalization-collisions/audit.json` | `normcollidectl verify` — the harness digest, after the binary was rebuilt | `normcollidectl write --harness …` |
| `evidence/us005-handshake-live-mapping.json` | `TestHandshakeLiveMappingEvidenceDocument` — byte identity with `HandshakeVerdictMapping()` | `RenderHandshakeLiveMappingDocument`, its own render path |
| `evidence/oracle-hierarchy/adjudication-register.json` | `oraclerankctl --check` — the register hashes the mapping's bytes | `oraclerankctl --root .`, which never reads the committed register |
| `evidence/linkage/*.json` | `internal/linkage` — `ConnectionCore` digest stale, `evidence.linkage.live-handshake-mapping` digest stale | `LINKAGE_REGENERATE=1`, which asserts byte-idempotence |

The linkage diff is digests and cited line numbers only (the `RejectStage` enum
shifted declarations below it in `handshake.rs`); the register diff is one
digest and one byte count, with 640 propositions / 589 agreements / 39
overrides unchanged. Worth stating plainly: **four separate records noticed this
change without being told to.** That is the binding working, not friction.

---

## 7b. Final suite state

`go test -timeout 40m ./...` with `VJWP_PROTECTED_STORE` set — exit **1**, and
the failing packages are exactly the five proven-baseline ones:

    internal/lab           internal/portplan      internal/formalplan   (named in the handoff)
    internal/formalcoverage  cmd/formalcoverctl                          (proven baseline in §7)

`internal/corpora`, `internal/normcollide`, `internal/deltaledger`,
`internal/diffregress`, `internal/ac5class`, `internal/linkage`,
`internal/oraclerank`, `cmd/corporactl` all pass. `cargo test` across the Rust
workspace: 47 test binaries, 0 failures. `make -C rust gates`: exit 0.

## 8. Recorded by name: what was NOT done

- Did **not** adjust any rule to make a collision disappear; no check was
  removed or weakened. The one deleted assertion (§6) asserted an absence the
  change refutes and was replaced by a strictly stronger pair.
- Did **not** edit a number in `evidence/normalization-collisions/audit.json`.
  Every count came from `normcollidectl write`, and `normcollidectl verify`
  agrees with a fresh run.
- Did **not** route around `normcollidectl`'s `--harness` requirement.
- Did **not** touch the ledger, `internal/deltaledger`, or
  `assurance/concurrency/results.json`. `deltaledgerctl --check` re-verified at
  exit 0 with the ledger head digest unchanged
  (`sha256:a44191d3c2db7850557e594e281e6a51badf2e913d9d3f0aa959fb973d84a56c`,
  56 records).
- Did **not** run AWS, benchmark, or Autobahn gates.
- Did **not** add `direction`, the `HS_*` reject codes, Java exception messages,
  the parsed status of a rejected response, `incomplete` byte counts, or the
  request path — each rejected under §2 with a reason.
- Did **not** score the 101 response head (zero census effect, and its `Date` is
  a clock reading).
- Did **not** merge to or push mainline.
- Did **not** claim the pinned-JDK baseline, the archive digest, or a
  proved-production grade. The grade is **BOUNDED**, as it was.

---

## 9. What is still open

- 29 of 49 is the **new ceiling, not a clean bill**. 23 cases still share an
  observation with another. The residual is argued in §1 to be structural at this
  tier, and the two largest classes (10 and 9) are argued from source; that
  argument is a **reading**, and a reading is not the same grade as a run.
- `CAND-TRANSPORT` and `CAND-CROSSARRAY` remain HYPOTHESIS.
- The surface enumeration is still not proved complete. A distinction none of the
  five read sites mentions still cannot be found by reading them.
- The exam still certifies at most 29 distinguishable answers out of 49 cases.
  **49/49 must never be stated without that ceiling.**
