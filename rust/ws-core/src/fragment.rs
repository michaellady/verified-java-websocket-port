//! Fragmentation plane (US-014): bounded inbound fragment reassembly
//! mirroring `org.java_websocket.framing.ContinuousFrame` accumulation
//! (migration map planned identity `ws_core::fragment::ContinuousFrame`).
//!
//! Semantics authority: derive.go `processDataFrame` — cumulative fragment
//! totals are checked only at starts and fins
//! ([`crate::framing::Draft6455::check_buffer_limit`], quirk Q23); a
//! non-fin continuation that overflows trips the adapter's own accounting
//! (`BUFFER_LIMIT_EXCEEDED`, no close code). Those gates live in
//! [`crate::framing::Draft6455::process_frame_continuous`]; this module
//! owns only the accumulator itself. The port enforces the reassembly cap
//! BEFORE every append (planned strengthening
//! note.fragmentation.per-append-buffer-cap: the reference retains the
//! bytes then leaves the counter stale; observables identical).
//!
//! Borrow note: the Codex-plane US-014 accumulator (`codex-import`
//! dca0fdb, `fragment.rs`) informed the shape review but was NOT grafted:
//! its plan-time sequence rejections and incremental cross-fragment UTF-8
//! feeding fire at different sites than the pinned Java runtime
//! (derive.go rejects fragment-sequence violations at PROCESS time and
//! validates assembled text strictly only at the fin) — the batch borrow
//! receipt records the divergence.

use crate::framing::Opcode;

/// The inbound continuation accumulator: the declared data opcode of the
/// open message (Java `Draft_6455.currentContinuousFrame` opcode) and the
/// payload accumulated so far.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContinuousFrame {
    opcode: Option<Opcode>,
    payload: Vec<u8>,
}

impl ContinuousFrame {
    /// The declared opcode of the open fragment sequence, when one is open
    /// (derive.go `javaFragOpcode != 0`).
    #[must_use]
    pub fn active_opcode(&self) -> Option<Opcode> {
        self.opcode
    }

    /// Bytes accumulated so far (derive.go `len(javaFragPayload)`).
    #[must_use]
    pub fn buffered_len(&self) -> usize {
        self.payload.len()
    }

    /// Open a sequence from a non-fin data frame (derive.go fragment-start
    /// arm: the start payload replaces any prior buffer).
    pub(crate) fn start(&mut self, opcode: Opcode, payload: Vec<u8>) {
        self.opcode = Some(opcode);
        self.payload = payload;
    }

    /// Append one non-fin continuation payload (the caller has already run
    /// the add-bounded accounting gate).
    pub(crate) fn append(&mut self, bytes: &[u8]) {
        self.payload.extend_from_slice(bytes);
    }

    /// Close the sequence with the fin fragment's payload, returning the
    /// declared opcode and the assembled message (derive.go fin arm:
    /// assemble, then clear the sequence state).
    pub(crate) fn finish(&mut self, tail: &[u8]) -> (Opcode, Vec<u8>) {
        let opcode = self
            .opcode
            .take()
            .expect("finish requires an open fragment sequence");
        let mut assembled = std::mem::take(&mut self.payload);
        assembled.extend_from_slice(tail);
        (opcode, assembled)
    }
}
