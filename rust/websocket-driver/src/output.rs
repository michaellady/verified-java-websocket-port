use websocket_core::{
    ConnectionState, CoreOutput, SemanticEvent, TransportWrite, TypedProtocolFailure,
};

use crate::{DriverOutput, VecDeque};

#[derive(Debug)]
enum PendingOutput {
    Write(TransportWrite),
    Event(SemanticEvent),
    StateChanged(ConnectionState),
    Failure(TypedProtocolFailure),
}

#[derive(Debug, Default)]
pub(crate) struct OutputLedger {
    pending: VecDeque<PendingOutput>,
    offered: Option<TransportWrite>,
    cursor: usize,
    batch_writes_remaining: usize,
    flush_due: bool,
}

impl OutputLedger {
    pub(crate) fn append_step(
        &mut self,
        outputs: Vec<CoreOutput>,
        failure: Option<TypedProtocolFailure>,
    ) -> bool {
        let writes = outputs
            .iter()
            .filter(|output| matches!(output, CoreOutput::TransportWrite(_)))
            .count();
        self.batch_writes_remaining = self
            .batch_writes_remaining
            .checked_add(writes)
            .expect("bounded write entry accounting");

        let mut closed = false;
        for output in outputs {
            match output {
                CoreOutput::TransportWrite(write) => {
                    self.pending.push_back(PendingOutput::Write(write));
                }
                CoreOutput::SemanticEvent(event) => {
                    self.pending.push_back(PendingOutput::Event(event));
                }
                CoreOutput::StateChanged(ConnectionState::Closed) => closed = true,
                CoreOutput::StateChanged(state) => {
                    self.pending.push_back(PendingOutput::StateChanged(state));
                }
            }
        }
        if let Some(failure) = failure {
            self.pending.push_back(PendingOutput::Failure(failure));
        }
        closed
    }

    pub(crate) fn write_remaining(&self) -> usize {
        self.offered
            .as_ref()
            .map_or(0, |write| write.as_slice().len())
            .saturating_sub(self.cursor)
    }

    pub(crate) fn apply_progress(&mut self, bytes: usize) -> Result<(), usize> {
        let remaining = self.write_remaining();
        if remaining == 0 || bytes > remaining {
            return Err(remaining);
        }
        if bytes == 0 {
            return Ok(());
        }

        self.cursor += bytes;
        let offered_length = self
            .offered
            .as_ref()
            .map_or(0, |write| write.as_slice().len());
        if self.cursor == offered_length {
            self.offered = None;
            self.cursor = 0;
            self.batch_writes_remaining = self
                .batch_writes_remaining
                .checked_sub(1)
                .expect("a promoted write belongs to the current batch");
            if self.batch_writes_remaining == 0 {
                self.flush_due = true;
            }
        }
        Ok(())
    }

    pub(crate) fn has_pending_output(&self) -> bool {
        self.offered.is_some() || !self.pending.is_empty()
    }

    pub(crate) fn take_flush_due(&mut self) -> bool {
        let flush_due = self.flush_due;
        self.flush_due = false;
        flush_due
    }

    pub(crate) fn next(&mut self) -> Option<DriverOutput<'_>> {
        if self.offered.is_none() && matches!(self.pending.front(), Some(PendingOutput::Write(_))) {
            let Some(PendingOutput::Write(write)) = self.pending.pop_front() else {
                unreachable!("front was checked as a write")
            };
            self.offered = Some(write);
        }
        if let Some(write) = self.offered.as_ref() {
            return Some(DriverOutput::Write(&write.as_slice()[self.cursor..]));
        }
        match self.pending.pop_front() {
            Some(PendingOutput::Event(event)) => Some(DriverOutput::Event(event)),
            Some(PendingOutput::StateChanged(state)) => Some(DriverOutput::StateChanged(state)),
            Some(PendingOutput::Failure(failure)) => Some(DriverOutput::Failure(failure)),
            Some(PendingOutput::Write(_)) => unreachable!("write was promoted before pop"),
            None => None,
        }
    }

    pub(crate) fn abort_undrainable_writes(&mut self) {
        self.offered = None;
        self.cursor = 0;
        self.batch_writes_remaining = 0;
        self.flush_due = false;
        self.pending
            .retain(|output| !matches!(output, PendingOutput::Write(_)));
    }
}

#[cfg(kani)]
mod proofs {
    use super::OutputLedger;
    use crate::DriverOutput;
    use websocket_core::{
        ClientRequestDescriptor, ConnectionConfig, ConnectionCore, ConnectionLimits,
        ConnectionState, CoreInput, CoreOutput, LocalCommand, Role,
    };

    /// Exact number of transport acknowledgement installments per harness run.
    const INSTALLMENTS: usize = 3;

    /// Runs one real incumbent core step and returns both its ordered outputs
    /// and the exact transport bytes the core itself authored.
    ///
    /// Byte attribution is structural: [`websocket_core::TransportWrite`] has no
    /// public constructor, so the only transport bytes this crate can ever hold
    /// are bytes an incumbent [`ConnectionCore`] step produced.
    fn core_authored_step() -> (Vec<CoreOutput>, Vec<u8>) {
        let config = ConnectionConfig::try_from(ConnectionLimits::default())
            .expect("default connection limits are valid");
        let mut core = ConnectionCore::new(config, Role::Client);
        let descriptor =
            ClientRequestDescriptor::try_new("/", "h").expect("origin-form target and Host");
        let result = core.step(CoreInput::Command(LocalCommand::StartClientHandshake {
            descriptor,
            nonce: [0_u8; 16],
        }));
        assert!(
            result.failure().is_none(),
            "the incumbent core accepted the handshake command"
        );
        let outputs: Vec<CoreOutput> = result.outputs().cloned().collect();
        let mut authored = Vec::new();
        for output in &outputs {
            if let CoreOutput::TransportWrite(write) = output {
                authored.extend_from_slice(write.as_slice());
            }
        }
        (outputs, authored)
    }

    /// The driver transports the incumbent core's bytes and derives none of its
    /// own: every offered suffix is exactly `core_bytes[acknowledged..]`, the
    /// acknowledged installments reconstruct the core stream once and in order,
    /// and over-acknowledgement is refused without mutating the cursor.
    #[kani::proof]
    #[kani::unwind(256)]
    fn prove_core_write_transport_conservation() {
        let (outputs, core_bytes) = core_authored_step();
        let total = core_bytes.len();
        assert!(total > 0, "the core step authored transport bytes");

        let mut ledger = OutputLedger::default();
        assert!(
            !ledger.append_step(outputs, None),
            "an opening handshake write is not a terminal transition"
        );

        let mut acknowledged = 0_usize;
        for _ in 0..INSTALLMENTS {
            let remaining = total - acknowledged;
            let offered = match ledger.next() {
                Some(DriverOutput::Write(bytes)) => {
                    assert!(remaining > 0, "no write is offered after the core drained");
                    assert_eq!(
                        bytes.len(),
                        remaining,
                        "the offered suffix is the exact undelivered tail of the core write"
                    );
                    let index: usize = kani::any();
                    kani::assume(index < bytes.len());
                    assert_eq!(
                        bytes[index],
                        core_bytes[acknowledged + index],
                        "every transported byte is the core's own byte at the core's own offset"
                    );
                    bytes.len()
                }
                Some(_) => {
                    unreachable!("a non-transport output preceded the undrained core write")
                }
                None => {
                    assert_eq!(remaining, 0, "the ledger withheld undelivered core bytes");
                    0
                }
            };
            assert_eq!(ledger.write_remaining(), offered);
            if offered == 0 {
                continue;
            }
            assert_eq!(
                ledger.apply_progress(offered + 1),
                Err(offered),
                "acknowledgement past the offered suffix is refused"
            );
            assert_eq!(
                ledger.write_remaining(),
                offered,
                "a refused acknowledgement mutates no cursor"
            );

            let accepted: usize = kani::any();
            kani::assume(accepted <= offered);
            assert_eq!(ledger.apply_progress(accepted), Ok(()));
            acknowledged += accepted;
        }

        assert!(acknowledged <= total, "no byte is acknowledged twice");
        if acknowledged == total {
            assert_eq!(ledger.write_remaining(), 0);
            assert!(!ledger.has_pending_output(), "the core write is not re-offered");
            assert!(
                ledger.take_flush_due(),
                "a fully drained core batch reports exactly one flush"
            );
        }
    }

    /// The driver never manufactures transport bytes: a core step that authored
    /// no [`CoreOutput::TransportWrite`] yields no [`DriverOutput::Write`], no
    /// drainable suffix, and no flush.
    #[kani::proof]
    #[kani::unwind(2)]
    fn prove_no_transport_write_without_a_core_write() {
        let state = if kani::any::<bool>() {
            ConnectionState::Open
        } else {
            ConnectionState::Closing
        };
        let mut ledger = OutputLedger::default();
        assert!(!ledger.append_step(vec![CoreOutput::StateChanged(state)], None));
        assert_eq!(ledger.write_remaining(), 0);
        assert_eq!(
            ledger.apply_progress(1),
            Err(0),
            "no suffix exists to acknowledge"
        );

        match ledger.next() {
            Some(DriverOutput::Write(_)) => {
                unreachable!("the driver offered transport bytes the core never authored")
            }
            Some(DriverOutput::StateChanged(observed)) => assert_eq!(observed, state),
            other => unreachable!("unexpected ledger output {other:?}"),
        }
        assert!(!ledger.has_pending_output());
        assert!(!ledger.take_flush_due(), "no core write means no flush");
        assert_eq!(ledger.write_remaining(), 0);

        match ledger.next() {
            None => {}
            Some(DriverOutput::Write(_)) => {
                unreachable!("the driver offered transport bytes after the core step drained")
            }
            Some(_) => unreachable!("unexpected trailing ledger output"),
        }
    }
}
