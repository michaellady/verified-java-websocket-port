//! Pull-driven single-owner scheduling for [`websocket_core::ConnectionCore`].
//!
//! Producers share only a bounded nonblocking command handle. One owner keeps
//! the mutable protocol core, ordered outputs, partial-write cursor, and
//! terminal state private. Transports remain outside this crate.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod output;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};

use websocket_core::{
    ConnectionConfig, ConnectionCore, ConnectionState, CoreInput, CoreStepObservation,
    LocalCommand, Role, SemanticEvent, TransportBytes, TypedProtocolFailure,
};

use output::OutputLedger;

/// Builds one bounded producer handle and its sole pull-driven owner.
#[must_use]
pub fn connection_driver(config: ConnectionConfig, role: Role) -> (CommandHandle, ConnectionOwner) {
    let limits = *config.limits();
    let capacity = usize::try_from(limits.command_queue_entries)
        .expect("ConnectionConfig already proved command capacity fits usize");
    let _aggregate_entries = limits
        .command_queue_entries
        .checked_add(limits.write_queue_entries)
        .and_then(|value| value.checked_add(limits.event_queue_entries))
        .and_then(|value| usize::try_from(value).ok())
        .expect("ConnectionConfig bounds make driver entry arithmetic representable");
    let (sender, receiver) = mpsc::sync_channel(capacity);
    let gate = Arc::new(AdmissionGate {
        accepting: AtomicBool::new(true),
        in_flight: AtomicUsize::new(0),
        retained_bytes: AtomicUsize::new(0),
    });
    let handle = CommandHandle {
        sender,
        gate: Arc::clone(&gate),
        limits,
    };
    let owner = ConnectionOwner {
        core: ConnectionCore::new(config, role),
        receiver,
        gate,
        held_command: None,
        output: OutputLedger::default(),
        command_turn: true,
        eof_latched: false,
        shutdown_latched: false,
        eof_applied: false,
        terminal_pending: false,
        terminal_ready: false,
        terminal_delivered: false,
        terminal_outcome: TerminalOutcome::Closed,
        dispositions: VecDeque::new(),
        producers_dropped_reported: false,
        last_core_observation: None,
        core_step_sequence: 0,
    };
    (handle, owner)
}

#[derive(Debug)]
struct AdmissionGate {
    accepting: AtomicBool,
    in_flight: AtomicUsize,
    retained_bytes: AtomicUsize,
}

struct InFlightGuard<'a> {
    gate: &'a AdmissionGate,
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        let previous = self.gate.in_flight.fetch_sub(1, Ordering::SeqCst);
        debug_assert!(previous > 0, "in-flight admission counter underflow");
    }
}

/// Cloneable nonblocking producer for the owner's exact bounded command queue.
#[derive(Clone, Debug)]
pub struct CommandHandle {
    sender: mpsc::SyncSender<CommandEnvelope>,
    gate: Arc<AdmissionGate>,
    limits: websocket_core::ConnectionLimits,
}

impl CommandHandle {
    /// Attempts to retain one command without waiting for queue capacity.
    pub fn try_enqueue(&self, command: LocalCommand) -> Result<(), EnqueueError> {
        let (attempted, class_maximum) = command_charge(&command, &self.limits);
        if attempted > class_maximum {
            return Err(EnqueueError::LimitExceeded {
                command,
                attempted,
                maximum: class_maximum,
            });
        }
        if !self.gate.accepting.load(Ordering::SeqCst) {
            return Err(EnqueueError::ShuttingDown(command));
        }
        if self
            .gate
            .in_flight
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                value.checked_add(1)
            })
            .is_err()
        {
            self.gate.accepting.store(false, Ordering::SeqCst);
            return Err(EnqueueError::ShuttingDown(command));
        }
        let _guard = InFlightGuard { gate: &self.gate };
        if !self.gate.accepting.load(Ordering::SeqCst) {
            return Err(EnqueueError::ShuttingDown(command));
        }
        let logical_bytes = usize::try_from(attempted)
            .expect("validated command charge fits the configured platform budget");
        let aggregate_maximum = usize::try_from(self.limits.total_buffered_bytes)
            .expect("ConnectionConfig proved the aggregate budget fits usize");
        match self
            .gate
            .retained_bytes
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current
                    .checked_add(logical_bytes)
                    .filter(|next| *next <= aggregate_maximum)
            }) {
            Ok(_) => {}
            Err(current) => {
                return Err(EnqueueError::LimitExceeded {
                    command,
                    attempted: u64::try_from(current.saturating_add(logical_bytes))
                        .unwrap_or(u64::MAX),
                    maximum: self.limits.total_buffered_bytes,
                });
            }
        }
        let retained = RetainedBytes {
            gate: Arc::clone(&self.gate),
            logical_bytes,
        };
        let envelope = CommandEnvelope {
            command: Some(command),
            _retained: retained,
        };
        match self.sender.try_send(envelope) {
            Ok(()) => Ok(()),
            Err(mpsc::TrySendError::Full(mut envelope)) => {
                Err(EnqueueError::Full(envelope.take_command()))
            }
            Err(mpsc::TrySendError::Disconnected(mut envelope)) => {
                Err(EnqueueError::ReceiverDropped(envelope.take_command()))
            }
        }
    }
}

#[derive(Debug)]
struct CommandEnvelope {
    command: Option<LocalCommand>,
    _retained: RetainedBytes,
}

impl CommandEnvelope {
    fn take_command(&mut self) -> LocalCommand {
        self.command
            .take()
            .expect("command envelope owns one command")
    }
}

#[derive(Debug)]
struct RetainedBytes {
    gate: Arc<AdmissionGate>,
    logical_bytes: usize,
}

impl Drop for RetainedBytes {
    fn drop(&mut self) {
        release_retained(&self.gate, self.logical_bytes);
    }
}

fn release_retained(gate: &AdmissionGate, logical_bytes: usize) {
    let result = gate
        .retained_bytes
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
            current.checked_sub(logical_bytes)
        });
    debug_assert!(result.is_ok(), "retained command byte counter underflow");
}

fn command_charge(command: &LocalCommand, limits: &websocket_core::ConnectionLimits) -> (u64, u64) {
    let length = match command {
        LocalCommand::StartClientHandshake { descriptor, .. } => descriptor
            .request_target()
            .len()
            .saturating_add(descriptor.host().len())
            .saturating_add(16),
        LocalCommand::SendText { payload, .. } => payload.len(),
        LocalCommand::SendBinary { payload, .. }
        | LocalCommand::SendFragment { payload, .. }
        | LocalCommand::SendPing { payload, .. }
        | LocalCommand::SendPong { payload, .. } => payload.len(),
        LocalCommand::Close { reason, code, .. } => {
            reason.len().saturating_add(usize::from(code.is_some()) * 2)
        }
    };
    let maximum = match command {
        LocalCommand::StartClientHandshake { .. } => limits.handshake_bytes,
        _ => limits.total_buffered_bytes,
    };
    (u64::try_from(length).unwrap_or(u64::MAX), maximum)
}

/// A rejected enqueue that always returns ownership of the command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnqueueError {
    /// The exact configured entry capacity is already retained.
    Full(LocalCommand),
    /// Producer admission closed before the queue operation committed.
    ShuttingDown(LocalCommand),
    /// The sole owner receiver no longer exists.
    ReceiverDropped(LocalCommand),
    /// The command's logical retained bytes exceed its configured class cap.
    LimitExceeded {
        /// Command whose ownership was not retained.
        command: LocalCommand,
        /// Logical bytes the command would retain.
        attempted: u64,
        /// Configured logical-byte maximum.
        maximum: u64,
    },
}

/// One transport fact admitted to [`ConnectionOwner::poll`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DriverInput<'a> {
    /// Gives queued owner work an execution turn.
    Wake,
    /// Supplies one borrowed buffer; the driver never retains it.
    Inbound(TransportBytes<'a>),
    /// Acknowledges an exact prefix of the currently offered write suffix.
    WriteProgress {
        /// Number of bytes accepted by the transport.
        bytes: usize,
    },
    /// Reports that the read side reached EOF.
    TransportEof,
    /// Reports that the adapter can provide no more transport service.
    Shutdown,
}

/// Why borrowed inbound bytes were not consumed by this poll.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeferredReason {
    /// An earlier ordered output still requires delivery.
    OutputPending,
    /// Alternation assigned this quiescent transition to a queued command.
    CommandTurn,
    /// A complete write must first be reported to the protocol core.
    FlushPending,
}

/// Why a driver input was rejected without mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriverInputError {
    /// Write progress exceeded the exact offered suffix or no suffix existed.
    InvalidWriteProgress {
        /// Reported progress.
        attempted: usize,
        /// Currently offered suffix length.
        remaining: usize,
    },
}

/// Exact consumption result for the supplied driver input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputDisposition {
    /// The input fact was consumed; inbound reports its complete byte count.
    Consumed {
        /// Borrowed inbound bytes consumed, otherwise zero.
        bytes: usize,
    },
    /// The adapter must retry the identical borrowed inbound bytes.
    Deferred(DeferredReason),
    /// The input was invalid and changed no driver state.
    Rejected(DriverInputError),
}

/// Exactly-once owner disposition of an accepted producer command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandDisposition {
    /// The core accepted and applied this command.
    Applied(LocalCommand),
    /// The core rejected this command with a typed nonterminal or terminal failure.
    Rejected {
        /// Accepted command being disposed.
        command: LocalCommand,
        /// Exact core failure.
        failure: TypedProtocolFailure,
    },
    /// Terminal convergence rejected an already accepted queued command.
    TerminalRejected(LocalCommand),
    /// Every producer handle was dropped after queued work drained.
    ProducersDropped,
}

/// One normalized connection terminal result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TerminalOutcome {
    /// The core reached its one terminal `Closed` state.
    Closed,
}

/// The next exact ordered driver output.
#[derive(Debug, Eq, PartialEq)]
pub enum DriverOutput<'owner> {
    /// No output is currently pending.
    Idle,
    /// Exact undrained suffix of the front transport write.
    Write(&'owner [u8]),
    /// One owned semantic event, delivered outside the core call.
    Event(SemanticEvent),
    /// One nonterminal lifecycle transition.
    StateChanged(ConnectionState),
    /// One typed core failure after earlier outputs from the same step.
    Failure(TypedProtocolFailure),
    /// The single normalized terminal delivery.
    Terminal(TerminalOutcome),
}

/// Result of one bounded owner transition.
#[derive(Debug, Eq, PartialEq)]
pub struct PollResult<'owner> {
    /// Disposition of the supplied driver input.
    pub input: InputDisposition,
    /// At most one command disposition.
    pub command: Option<CommandDisposition>,
    /// Next ordered output or `Idle`.
    pub output: DriverOutput<'owner>,
    /// Current protocol lifecycle state.
    pub state: ConnectionState,
}

/// Input accepted only for a diagnostic observation after terminal delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClosedObservationInput<'a> {
    /// Borrowed bytes presented to the already-closed core.
    Inbound(TransportBytes<'a>),
    /// Transport EOF presented to the already-closed core.
    TransportEof,
}

/// Result of observing the incumbent core's terminal-state behavior.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosedObservationResult {
    /// Typed failure, if the core rejects the terminal-state input.
    pub failure: Option<TypedProtocolFailure>,
    /// Lifecycle state after the observation.
    pub state: ConnectionState,
}

/// Sole mutable owner of protocol, ordering, write progress, and terminal state.
#[derive(Debug)]
pub struct ConnectionOwner {
    core: ConnectionCore,
    receiver: mpsc::Receiver<CommandEnvelope>,
    gate: Arc<AdmissionGate>,
    held_command: Option<CommandEnvelope>,
    output: OutputLedger,
    command_turn: bool,
    eof_latched: bool,
    shutdown_latched: bool,
    eof_applied: bool,
    terminal_pending: bool,
    terminal_ready: bool,
    terminal_delivered: bool,
    terminal_outcome: TerminalOutcome,
    dispositions: VecDeque<CommandDisposition>,
    producers_dropped_reported: bool,
    last_core_observation: Option<CoreStepObservation>,
    core_step_sequence: u64,
}

impl ConnectionOwner {
    /// Returns the incumbent core's current public lifecycle state.
    #[must_use]
    pub const fn state(&self) -> ConnectionState {
        self.core.state()
    }

    /// Returns the read-only observation from the most recent core step.
    #[must_use]
    pub const fn last_core_observation(&self) -> Option<&CoreStepObservation> {
        self.last_core_observation.as_ref()
    }

    /// Returns the monotonic sequence and observation of the latest core step.
    #[must_use]
    pub const fn last_core_step(&self) -> Option<(u64, &CoreStepObservation)> {
        match self.last_core_observation.as_ref() {
            Some(observation) => Some((self.core_step_sequence, observation)),
            None => None,
        }
    }

    /// Observes one input against an already-closed core without reopening
    /// producer admission or producing another terminal delivery.
    pub fn observe_closed(
        &mut self,
        input: ClosedObservationInput<'_>,
    ) -> Option<ClosedObservationResult> {
        if self.core.state() != ConnectionState::Closed {
            return None;
        }
        let input = match input {
            ClosedObservationInput::Inbound(bytes) => CoreInput::Transport(bytes),
            ClosedObservationInput::TransportEof => CoreInput::TransportEof,
        };
        let result = self.core.step(input);
        self.core_step_sequence = self.core_step_sequence.checked_add(1)?;
        self.last_core_observation = Some(self.core.last_step_observation().clone());
        Some(ClosedObservationResult {
            failure: result.failure().cloned(),
            state: result.state(),
        })
    }

    /// Performs at most one owner transition and returns the next ordered output.
    pub fn poll<'owner>(&'owner mut self, input: DriverInput<'_>) -> PollResult<'owner> {
        let mut input_disposition = consumed(&input);
        match input {
            DriverInput::Shutdown => {
                self.shutdown_latched = true;
                self.gate.accepting.store(false, Ordering::SeqCst);
                self.abort_undrainable_writes();
            }
            DriverInput::TransportEof => {
                self.eof_latched = true;
                self.gate.accepting.store(false, Ordering::SeqCst);
            }
            _ => {}
        }

        if let DriverInput::WriteProgress { bytes } = input {
            if let Err(remaining) = self.output.apply_progress(bytes) {
                input_disposition =
                    InputDisposition::Rejected(DriverInputError::InvalidWriteProgress {
                        attempted: bytes,
                        remaining,
                    });
            }
            let command = self.next_disposition();
            let state = self.core.state();
            let output = self.next_output();
            return PollResult {
                input: input_disposition,
                command,
                output,
                state,
            };
        }

        if self.has_pending_output() {
            if matches!(input, DriverInput::Inbound(_)) {
                input_disposition = InputDisposition::Deferred(DeferredReason::OutputPending);
            }
            let command = self.next_disposition();
            let state = self.core.state();
            let output = self.next_output();
            return PollResult {
                input: input_disposition,
                command,
                output,
                state,
            };
        }

        let mut command_disposition = None;
        if self.output.take_flush_due() {
            if matches!(input, DriverInput::Inbound(_)) {
                input_disposition = InputDisposition::Deferred(DeferredReason::FlushPending);
            }
            let result = self.core.step(CoreInput::TransportWriteFlushed);
            self.commit(result);
        } else if (self.shutdown_latched || self.eof_latched) && !self.eof_applied {
            self.eof_applied = true;
            let result = self.core.step(CoreInput::TransportEof);
            self.commit(result);
        } else if !self.terminal_pending && !self.terminal_delivered {
            self.fill_held_command();
            match input {
                DriverInput::Inbound(_) if self.held_command.is_some() && self.command_turn => {
                    input_disposition = InputDisposition::Deferred(DeferredReason::CommandTurn);
                    let envelope = self.held_command.take().expect("checked held command");
                    command_disposition = Some(self.apply_command(envelope));
                    self.command_turn = false;
                }
                DriverInput::Inbound(bytes) => {
                    let result = self.core.step(CoreInput::Transport(bytes));
                    self.commit(result);
                    self.command_turn = true;
                }
                DriverInput::Wake if self.held_command.is_some() => {
                    let envelope = self.held_command.take().expect("checked held command");
                    command_disposition = Some(self.apply_command(envelope));
                    self.command_turn = false;
                }
                _ => {}
            }
        }

        self.prepare_terminal();
        let command = command_disposition.or_else(|| self.next_disposition());
        let state = self.core.state();
        let output = if command.is_some() && self.terminal_pending && !self.has_pending_output() {
            DriverOutput::Idle
        } else {
            self.next_output()
        };
        PollResult {
            input: input_disposition,
            command,
            output,
            state,
        }
    }

    fn apply_command(&mut self, mut envelope: CommandEnvelope) -> CommandDisposition {
        let command = envelope.take_command();
        let result = self.core.step(CoreInput::Command(command.clone()));
        let failure = result.failure().cloned();
        self.commit(result);
        drop(envelope);
        match failure {
            Some(failure) => CommandDisposition::Rejected { command, failure },
            None => CommandDisposition::Applied(command),
        }
    }

    fn commit(&mut self, result: websocket_core::StepResult) {
        self.core_step_sequence = self
            .core_step_sequence
            .checked_add(1)
            .expect("bounded owner step sequence");
        self.last_core_observation = Some(self.core.last_step_observation().clone());
        let state = result.state();
        let failure = result.failure().cloned();
        let outputs: Vec<_> = result.outputs().cloned().collect();
        if self.output.append_step(outputs, failure) {
            self.begin_terminal();
        }
        if state == ConnectionState::Closed {
            self.begin_terminal();
        }
    }

    fn begin_terminal(&mut self) {
        self.gate.accepting.store(false, Ordering::SeqCst);
        self.terminal_pending = true;
        self.terminal_ready = false;
    }

    fn fill_held_command(&mut self) {
        if self.held_command.is_some() {
            return;
        }
        match self.receiver.try_recv() {
            Ok(command) => self.held_command = Some(command),
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                if !self.producers_dropped_reported {
                    self.dispositions
                        .push_back(CommandDisposition::ProducersDropped);
                    self.producers_dropped_reported = true;
                }
            }
        }
    }

    fn prepare_terminal(&mut self) {
        if !self.terminal_pending
            || self.has_pending_output()
            || self.gate.in_flight.load(Ordering::SeqCst) != 0
        {
            return;
        }
        if let Some(mut envelope) = self.held_command.take() {
            let command = envelope.take_command();
            self.dispositions
                .push_back(CommandDisposition::TerminalRejected(command));
        }
        while let Ok(mut envelope) = self.receiver.try_recv() {
            let command = envelope.take_command();
            self.dispositions
                .push_back(CommandDisposition::TerminalRejected(command));
        }
        self.terminal_ready = true;
    }

    fn next_disposition(&mut self) -> Option<CommandDisposition> {
        self.dispositions.pop_front()
    }

    fn has_pending_output(&self) -> bool {
        self.output.has_pending_output()
    }

    fn next_output(&mut self) -> DriverOutput<'_> {
        match self.output.next() {
            Some(output) => output,
            None if self.terminal_ready && self.dispositions.is_empty() => {
                self.terminal_pending = false;
                self.terminal_ready = false;
                self.terminal_delivered = true;
                DriverOutput::Terminal(self.terminal_outcome.clone())
            }
            None => DriverOutput::Idle,
        }
    }

    fn abort_undrainable_writes(&mut self) {
        self.output.abort_undrainable_writes();
    }
}

fn consumed(input: &DriverInput<'_>) -> InputDisposition {
    InputDisposition::Consumed {
        bytes: match input {
            DriverInput::Inbound(bytes) => bytes.as_slice().len(),
            _ => 0,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use websocket_core::{ConnectionLimits, Role};

    #[test]
    fn terminal_waits_for_an_in_flight_admission_to_finish() {
        let config = ConnectionConfig::try_from(ConnectionLimits::default()).unwrap();
        let (handle, mut owner) = connection_driver(config, Role::Server);
        assert!(matches!(
            owner.poll(DriverInput::Shutdown).output,
            DriverOutput::Failure(_)
        ));
        handle.gate.in_flight.store(1, Ordering::SeqCst);
        assert!(matches!(
            owner.poll(DriverInput::Wake).output,
            DriverOutput::Idle
        ));
        handle.gate.in_flight.store(0, Ordering::SeqCst);
        assert!(matches!(
            owner.poll(DriverInput::Wake).output,
            DriverOutput::Terminal(_)
        ));
    }
}
