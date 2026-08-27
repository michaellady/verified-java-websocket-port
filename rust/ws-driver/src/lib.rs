//! # ws-driver: the pull-driven single-owner driver seam for `ws_core` (US-017)
//!
//! Multiple producers share only the bounded nonblocking
//! [`ws_core::CommandSender`] handle; exactly ONE owner holds the
//! [`ws_core::ConnectionCore`], drains its ordered outputs, tracks
//! partial-write progress, and delivers the terminal outcome exactly once.
//! Transports stay outside this crate (the US-018 adapters own sockets); the
//! driver is deterministic and clock-free like the core it wraps.
//!
//! ## Borrow attribution (owner strategy: borrow with attribution)
//!
//! Adapted from the Codex-plane US-017 `websocket-driver` (codex-import
//! 6a7606a): the pull-driven `poll(DriverInput) -> PollResult` shape, the
//! partial-write cursor with exact `WriteProgress` validation, the
//! inbound-vs-command alternation turn, EOF/shutdown latching, the
//! exactly-once `Terminal` delivery, and the terminal rejection of still
//! queued commands are their design. **Adaptation to `ws_core`:** their
//! `AdmissionGate` + `mpsc::sync_channel` producer machinery is NOT adopted —
//! the incumbent `ws_core` bounded multi-producer command channel
//! ([`ws_core::CommandQueue`] / [`ws_core::CommandSender`], the US-009 AC4
//! boundary) is the single producer seam, so no second admission mechanism
//! can drift from it; their `StepResult`-batch commit ledger is NOT adopted —
//! the core's own bounded event/write queues are the ordered ledger and the
//! driver drains them, never duplicating protocol state (the US-009
//! "adapters cannot duplicate protocol state" promise). Their
//! `ProducersDropped` disposition is NOT adopted: the `ws_core` channel has
//! no disconnect signal by design, so producer lifecycle belongs to the
//! embedding adapter.
//!
//! The six `fuzz-seeds/us017/*.seed` schedule seeds are adopted byte-verbatim
//! with attribution; `tests/driver_contract.rs` re-derives each seed's
//! property against this driver with a deterministic schedule interpreter.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::VecDeque;

use ws_core::{
    CommandQueue, CommandSender, ConnectionConfig, ConnectionCore, InitialState, Input,
    LocalCommand, ReadyState, Role, SemanticEvent, TransportWrite, TypedProtocolFailure,
};

/// Builds the bounded producer handle and its sole pull-driven owner for a
/// fresh (`NotYetConnected`) connection.
#[must_use]
pub fn connection_driver(
    config: ConnectionConfig,
    role: Role,
) -> (CommandSender, ConnectionDriver) {
    let (queue, sender) = CommandQueue::new(&config);
    let core = ConnectionCore::new(config, role);
    (sender, ConnectionDriver::new(core, queue))
}

/// Builds the driver for a post-handshake connection in a given corpus
/// state (test and fixture seam, mirroring
/// [`ws_core::ConnectionCore::new_in_state`]).
#[must_use]
pub fn connection_driver_in_state(
    config: ConnectionConfig,
    role: Role,
    state: InitialState,
) -> (CommandSender, ConnectionDriver) {
    let (queue, sender) = CommandQueue::new(&config);
    let core = ConnectionCore::new_in_state(config, role, state);
    (sender, ConnectionDriver::new(core, queue))
}

/// One transport fact admitted to [`ConnectionDriver::poll`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverInput<'a> {
    /// Gives queued owner work (a command, a latched EOF, output draining)
    /// an execution turn without supplying transport facts.
    Wake,
    /// One borrowed inbound byte chunk; the driver never retains it — a
    /// deferred disposition means the adapter must retry the identical
    /// bytes.
    Inbound(&'a [u8]),
    /// Acknowledges that the transport accepted exactly this many bytes of
    /// the currently offered write suffix.
    WriteProgress {
        /// Bytes the transport accepted.
        bytes: usize,
    },
    /// The read side reached EOF.
    TransportEof,
    /// The adapter can provide no further transport service: pending wire
    /// output is undeliverable and is aborted; the protocol EOF still
    /// applies.
    Shutdown,
}

/// Why borrowed inbound bytes were not consumed by this poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeferredReason {
    /// A committed wire write is still in flight; it must finish before new
    /// inbound facts apply (queued events need no such gate — the core's
    /// FIFO event queue preserves their order across inputs).
    OutputPending,
    /// The fairness alternation assigned this turn to a queued command.
    CommandTurn,
    /// The core refused the chunk with its non-fatal backpressure code; the
    /// adapter drains outputs (by polling) and retries the identical bytes.
    Backpressure,
}

/// Why a driver input was rejected without any state change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverInputError {
    /// Write progress exceeded the offered suffix, or no write was offered.
    InvalidWriteProgress {
        /// Reported progress.
        attempted: usize,
        /// Currently offered suffix length.
        remaining: usize,
    },
}

/// Exact consumption result for the supplied driver input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputDisposition {
    /// The input fact was consumed; inbound reports its full byte count.
    Consumed {
        /// Borrowed inbound bytes consumed (zero for non-byte inputs).
        bytes: usize,
    },
    /// The adapter must retry the identical input.
    Deferred(DeferredReason),
    /// The input was invalid and changed nothing.
    Rejected(DriverInputError),
}

/// Exactly-once owner disposition of one accepted producer command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandDisposition {
    /// The core accepted and fully applied the command.
    Applied(LocalCommand),
    /// The core rejected the command with a typed failure.
    Rejected {
        /// The disposed command.
        command: LocalCommand,
        /// The exact typed core failure.
        failure: TypedProtocolFailure,
    },
    /// Terminal convergence rejected a command that was still queued when
    /// the connection closed.
    TerminalRejected(LocalCommand),
}

/// The single normalized terminal result: the core reached its one
/// absorbing `Closed` state and every ordered output before it delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalOutcome;

/// The next ordered driver output.
#[derive(Debug, PartialEq, Eq)]
pub enum DriverOutput<'owner> {
    /// Nothing is pending.
    Idle,
    /// The exact undrained suffix of the front transport write; the adapter
    /// reports progress with [`DriverInput::WriteProgress`].
    Write(&'owner [u8]),
    /// One owned semantic event (frame records, transitions, and detail
    /// events all travel this stream, as in the core).
    Event(SemanticEvent),
    /// One typed failure the core reported for an owner-applied input.
    Failure(TypedProtocolFailure),
    /// The exactly-once terminal delivery.
    Terminal(TerminalOutcome),
}

/// Result of one bounded owner transition.
#[derive(Debug, PartialEq, Eq)]
pub struct PollResult<'owner> {
    /// Disposition of the supplied input.
    pub input: InputDisposition,
    /// At most one command disposition surfaced by this poll.
    pub command: Option<CommandDisposition>,
    /// The next ordered output, or `Idle`.
    pub output: DriverOutput<'owner>,
    /// The core's current lifecycle state.
    pub state: ReadyState,
}

/// Sole mutable owner of the protocol core, output ordering, write
/// progress, and terminal delivery (US-017). Producers never touch it: they
/// hold only [`ws_core::CommandSender`] clones.
#[derive(Debug)]
pub struct ConnectionDriver {
    core: ConnectionCore,
    commands: CommandQueue,
    /// A command popped from the bounded channel and awaiting its turn.
    held: Option<LocalCommand>,
    /// The front transport write currently offered to the adapter.
    offered_write: Option<TransportWrite>,
    /// Bytes of the offered write already accepted by the transport.
    write_cursor: usize,
    /// Fairness alternation: after a command turn, inbound bytes get the
    /// next quiescent turn (borrowed design: codex 6a7606a `command_turn`).
    command_turn: bool,
    eof_latched: bool,
    shutdown_latched: bool,
    eof_applied: bool,
    terminal_delivered: bool,
    /// Queued command dispositions not yet surfaced (terminal rejections).
    dispositions: VecDeque<CommandDisposition>,
}

impl ConnectionDriver {
    fn new(core: ConnectionCore, commands: CommandQueue) -> ConnectionDriver {
        ConnectionDriver {
            core,
            commands,
            held: None,
            offered_write: None,
            write_cursor: 0,
            command_turn: true,
            eof_latched: false,
            shutdown_latched: false,
            eof_applied: false,
            terminal_delivered: false,
            dispositions: VecDeque::new(),
        }
    }

    /// Owner-side passthrough to
    /// [`ws_core::ConnectionCore::begin_client_handshake`] (the US-010
    /// construction entry point; not a producer command).
    ///
    /// # Errors
    ///
    /// Exactly the core's errors for that entry point.
    pub fn begin_client_handshake(
        &mut self,
        request_target: &str,
        host: &str,
    ) -> Result<(), TypedProtocolFailure> {
        self.core.begin_client_handshake(request_target, host)
    }

    /// The core's current lifecycle state.
    #[must_use]
    pub fn state(&self) -> ReadyState {
        self.core.state()
    }

    /// Snapshot of the core's corpus counters (read-only passthrough).
    #[must_use]
    pub fn counts(&self) -> ws_core::Counts {
        self.core.counts()
    }

    /// The governing close detail, once one exists (read-only passthrough).
    #[must_use]
    pub fn close_detail(&self) -> Option<&ws_core::CloseDetail> {
        self.core.close_detail()
    }

    /// Performs at most one owner transition and returns the next ordered
    /// output. Deterministic: the same input sequence yields the same
    /// result sequence.
    pub fn poll<'owner>(&'owner mut self, input: DriverInput<'_>) -> PollResult<'owner> {
        let mut input_disposition = consumed(&input);
        match input {
            DriverInput::Shutdown => {
                self.shutdown_latched = true;
                // Undeliverable wire output is aborted; the protocol EOF
                // below still applies (borrowed design: abort-undrainable-
                // writes on shutdown).
                self.offered_write = None;
                self.write_cursor = 0;
                self.drop_pending_writes();
            }
            DriverInput::TransportEof => {
                self.eof_latched = true;
            }
            DriverInput::WriteProgress { bytes } => {
                let remaining = self.write_remaining();
                if remaining == 0 || bytes > remaining {
                    input_disposition =
                        InputDisposition::Rejected(DriverInputError::InvalidWriteProgress {
                            attempted: bytes,
                            remaining,
                        });
                } else {
                    self.write_cursor += bytes;
                    if self.write_remaining() == 0 {
                        self.offered_write = None;
                        self.write_cursor = 0;
                    }
                }
                let command = self.dispositions.pop_front();
                let state = self.core.state();
                let output = self.next_output();
                return PollResult {
                    input: input_disposition,
                    command,
                    output,
                    state,
                };
            }
            DriverInput::Wake | DriverInput::Inbound(_) => {}
        }

        let mut command_disposition = None;
        if self.has_pending_output() {
            // Committed order protects itself: nothing new is applied while
            // an offered write or undrained event exists.
            if matches!(input, DriverInput::Inbound(_)) {
                input_disposition = InputDisposition::Deferred(DeferredReason::OutputPending);
            }
        } else if (self.eof_latched || self.shutdown_latched) && !self.eof_applied {
            // The latched transport EOF gets the first quiescent turn. The
            // core owns the semantics (Q20); a closed/poisoned core's
            // refusal is surfaced as a Failure output, never invented
            // around.
            self.eof_applied = true;
            if matches!(input, DriverInput::Inbound(_)) {
                input_disposition = InputDisposition::Deferred(DeferredReason::OutputPending);
            }
            if self.core.state() != ReadyState::Closed
                && let Err(failure) = self.core.handle(Input::TransportEof)
            {
                return self.finish_poll(input_disposition, None, Some(failure));
            }
        } else if !self.terminal_delivered {
            self.fill_held();
            match input {
                DriverInput::Inbound(_) if self.held.is_some() && self.command_turn => {
                    input_disposition = InputDisposition::Deferred(DeferredReason::CommandTurn);
                    command_disposition = self.apply_held_command();
                }
                DriverInput::Inbound(bytes) => {
                    self.command_turn = true;
                    match self.core.handle(Input::TransportBytes(bytes)) {
                        Ok(()) => {}
                        Err(failure) if !failure.code.is_fatal() => {
                            // Non-fatal backpressure: nothing was consumed;
                            // the adapter drains (by polling) and retries
                            // the identical bytes.
                            input_disposition =
                                InputDisposition::Deferred(DeferredReason::Backpressure);
                        }
                        Err(failure) => {
                            return self.finish_poll(input_disposition, None, Some(failure));
                        }
                    }
                }
                DriverInput::Wake if self.held.is_some() => {
                    command_disposition = self.apply_held_command();
                }
                _ => {}
            }
        }

        self.prepare_terminal();
        let command = command_disposition.or_else(|| self.dispositions.pop_front());
        self.finish_poll(input_disposition, command, None)
    }

    fn finish_poll<'owner>(
        &'owner mut self,
        input: InputDisposition,
        command: Option<CommandDisposition>,
        failure: Option<TypedProtocolFailure>,
    ) -> PollResult<'owner> {
        self.prepare_terminal();
        let state = self.core.state();
        let output = match failure {
            Some(failure) => DriverOutput::Failure(failure),
            None => self.next_output(),
        };
        PollResult {
            input,
            command,
            output,
            state,
        }
    }

    fn apply_held_command(&mut self) -> Option<CommandDisposition> {
        let command = self.held.take().expect("caller checked a held command");
        self.command_turn = false;
        match self.core.handle(Input::Command(command.clone())) {
            Ok(()) => Some(CommandDisposition::Applied(command)),
            Err(failure) if !failure.code.is_fatal() => {
                // Non-fatal backpressure: the command was not consumed; hold
                // it for the next turn after the adapter drains.
                self.held = Some(command);
                self.command_turn = true;
                None
            }
            Err(failure) => Some(CommandDisposition::Rejected { command, failure }),
        }
    }

    fn fill_held(&mut self) {
        if self.held.is_none() {
            self.held = self.commands.pop();
        }
    }

    /// After the core reaches its absorbing `Closed` state and no queued
    /// output remains, still-queued commands are disposed as
    /// `TerminalRejected` exactly once each (borrowed design: codex
    /// terminal convergence).
    fn prepare_terminal(&mut self) {
        if self.core.state() != ReadyState::Closed {
            return;
        }
        if let Some(command) = self.held.take() {
            self.dispositions
                .push_back(CommandDisposition::TerminalRejected(command));
        }
        while let Some(command) = self.commands.pop() {
            self.dispositions
                .push_back(CommandDisposition::TerminalRejected(command));
        }
    }

    fn drop_pending_writes(&mut self) {
        while self.core.next_write().is_some() {}
    }

    fn write_remaining(&self) -> usize {
        self.offered_write
            .as_ref()
            .map_or(0, |write| write.bytes.len() - self.write_cursor)
    }

    fn has_pending_output(&self) -> bool {
        self.offered_write.is_some()
    }

    fn next_output(&mut self) -> DriverOutput<'_> {
        // Writes drain before events so committed wire order can never be
        // reordered past a later step's output (FIFO owner order).
        if self.offered_write.is_none() {
            self.offered_write = self.core.next_write();
            self.write_cursor = 0;
        }
        if let Some(write) = self.offered_write.as_ref() {
            return DriverOutput::Write(&write.bytes[self.write_cursor..]);
        }
        if let Some(event) = self.core.next_event() {
            return DriverOutput::Event(event);
        }
        if self.core.state() == ReadyState::Closed
            && self.dispositions.is_empty()
            && !self.terminal_delivered
        {
            self.terminal_delivered = true;
            return DriverOutput::Terminal(TerminalOutcome);
        }
        DriverOutput::Idle
    }
}

fn consumed(input: &DriverInput<'_>) -> InputDisposition {
    InputDisposition::Consumed {
        bytes: match input {
            DriverInput::Inbound(bytes) => bytes.len(),
            _ => 0,
        },
    }
}
