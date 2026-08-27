use std::io::{Error, ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::{Duration, Instant};

use websocket_core::{ConnectionState, Role, TransportBytes};
use websocket_driver::{
    CommandDisposition, CommandHandle, ConnectionOwner, DriverInput, DriverOutput,
    InputDisposition, PollResult,
};

use crate::{
    AdapterCounters, AdapterObservation, AdapterReport, AdapterTermination, EventKind, IoBounds,
    SetupOutcome, SocketErrorKind,
};

#[derive(Clone, Copy)]
enum NextInput {
    Wake,
    Inbound,
    WriteProgress(usize),
    TransportEof,
    Shutdown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationFailure {
    Timeout,
    Io(SocketErrorKind),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IoDecision {
    Retry,
    Timeout,
    Fail(SocketErrorKind),
}

enum WriteResult {
    Progress {
        bytes: usize,
        flush_failure: Option<OperationFailure>,
    },
    Lost,
    Failed(OperationFailure),
}

struct ReportBuilder {
    report: AdapterReport,
    limit: usize,
}

impl ReportBuilder {
    fn connected(role: Role, limit: usize) -> Self {
        Self {
            report: AdapterReport {
                role,
                setup: SetupOutcome::Connected,
                termination: None,
                observations: Vec::new(),
                counters: AdapterCounters::default(),
                final_state: Some(ConnectionState::Connecting),
                terminal_count: 0,
            },
            limit,
        }
    }

    fn terminate(&mut self, cause: AdapterTermination) {
        if self.report.termination.is_none() {
            self.report.termination = Some(cause);
        }
    }

    fn observe(&mut self, observation: AdapterObservation) -> bool {
        if self.report.observations.len().saturating_add(1) < self.limit {
            self.report.observations.push(observation);
            return true;
        }
        self.terminate(AdapterTermination::ReportLimit);
        if self.report.observations.len() < self.limit {
            self.report
                .observations
                .push(AdapterObservation::AdapterFailure(
                    AdapterTermination::ReportLimit,
                ));
        }
        false
    }

    fn counter_failed(&mut self) {
        self.terminate(AdapterTermination::CounterOverflow);
    }
}

fn increment(value: &mut u64) -> bool {
    if let Some(next) = value.checked_add(1) {
        *value = next;
        true
    } else {
        false
    }
}

fn add(value: &mut u64, amount: usize) -> bool {
    let Ok(amount) = u64::try_from(amount) else {
        return false;
    };
    if let Some(next) = value.checked_add(amount) {
        *value = next;
        true
    } else {
        false
    }
}

pub(crate) fn drive_connected(
    mut stream: TcpStream,
    handle: CommandHandle,
    mut owner: ConnectionOwner,
    bounds: IoBounds,
    role: Role,
) -> AdapterReport {
    let _producer = handle;
    let spec = bounds.spec;
    let mut builder = ReportBuilder::connected(role, spec.max_report_entries);
    let mut read_buffer = vec![0_u8; spec.read_buffer_bytes];
    let mut pending_read = None;
    let mut next = NextInput::Wake;
    let mut eof_sent = false;
    let mut shutdown_sent = false;
    let mut shutdown_after_progress = None;

    loop {
        if builder.report.counters.owner_turns >= spec.max_owner_turns {
            builder.terminate(AdapterTermination::OwnerTurnLimit);
            let _ = builder.observe(AdapterObservation::AdapterFailure(
                AdapterTermination::OwnerTurnLimit,
            ));
            break;
        }
        if !increment(&mut builder.report.counters.owner_turns) {
            builder.counter_failed();
            break;
        }

        if matches!(next, NextInput::TransportEof) {
            eof_sent = true;
            if !increment(&mut builder.report.counters.eof_inputs) {
                builder.counter_failed();
                break;
            }
            if !builder.observe(AdapterObservation::TransportEof) {
                next = NextInput::Shutdown;
                continue;
            }
        }
        if matches!(next, NextInput::Shutdown) {
            shutdown_sent = true;
            if !increment(&mut builder.report.counters.shutdown_inputs) {
                builder.counter_failed();
                break;
            }
            let _ = builder.observe(AdapterObservation::Shutdown);
        }

        let polled = match next {
            NextInput::Wake => owner.poll(DriverInput::Wake),
            NextInput::Inbound => {
                let length = pending_read.unwrap_or(0);
                owner.poll(DriverInput::Inbound(TransportBytes::new(
                    &read_buffer[..length],
                )))
            }
            NextInput::WriteProgress(bytes) => owner.poll(DriverInput::WriteProgress { bytes }),
            NextInput::TransportEof => owner.poll(DriverInput::TransportEof),
            NextInput::Shutdown => owner.poll(DriverInput::Shutdown),
        };
        builder.report.final_state = Some(polled.state);

        if matches!(next, NextInput::Inbound) {
            let expected = pending_read.unwrap_or(0);
            match polled.input {
                InputDisposition::Consumed { bytes } if bytes == expected => pending_read = None,
                InputDisposition::Deferred(_) => {}
                InputDisposition::Consumed { .. } | InputDisposition::Rejected(_) => {
                    builder.terminate(AdapterTermination::InvariantViolation);
                    let _ = builder.observe(AdapterObservation::AdapterFailure(
                        AdapterTermination::InvariantViolation,
                    ));
                    if shutdown_sent {
                        break;
                    }
                    next = NextInput::Shutdown;
                    continue;
                }
            }
        }

        let recorded = record_poll(&mut builder, &polled);
        let terminal = matches!(polled.output, DriverOutput::Terminal(_));
        if terminal {
            builder.report.terminal_count = builder.report.terminal_count.saturating_add(1);
            if builder.report.termination.is_none() {
                builder.terminate(AdapterTermination::DriverTerminal);
            }
            break;
        }
        if !recorded {
            if shutdown_sent {
                break;
            }
            next = NextInput::Shutdown;
            continue;
        }

        if let Some(cause) = shutdown_after_progress.take() {
            builder.terminate(cause);
            if shutdown_sent {
                break;
            }
            next = NextInput::Shutdown;
            continue;
        }

        next = match polled.output {
            DriverOutput::Write(bytes) => {
                let offered = bytes.len();
                let requested = offered.min(spec.max_write_chunk_bytes);
                match write_with_deadline(
                    &mut stream,
                    &bytes[..requested],
                    spec.write_timeout,
                    &mut builder,
                ) {
                    WriteResult::Progress {
                        bytes,
                        flush_failure,
                    } => {
                        if bytes < offered
                            && !increment(&mut builder.report.counters.partial_writes)
                        {
                            builder.counter_failed();
                        }
                        if !builder.observe(AdapterObservation::WriteProgress { bytes }) {
                            NextInput::Shutdown
                        } else {
                            shutdown_after_progress = flush_failure.map(|failure| {
                                write_termination(failure, &mut builder.report.counters)
                            });
                            NextInput::WriteProgress(bytes)
                        }
                    }
                    WriteResult::Lost => {
                        builder.terminate(AdapterTermination::PeerServiceLost);
                        if shutdown_sent {
                            break;
                        }
                        NextInput::Shutdown
                    }
                    WriteResult::Failed(failure) => {
                        let cause = write_termination(failure, &mut builder.report.counters);
                        builder.terminate(cause);
                        if shutdown_sent {
                            break;
                        }
                        NextInput::Shutdown
                    }
                }
            }
            DriverOutput::Idle => {
                if shutdown_sent || eof_sent {
                    NextInput::Wake
                } else if pending_read.is_some() {
                    NextInput::Inbound
                } else {
                    match read_with_deadline(
                        &mut stream,
                        &mut read_buffer,
                        spec.read_timeout,
                        &mut builder,
                    ) {
                        Ok(0) => {
                            builder.terminate(AdapterTermination::PeerEof);
                            NextInput::TransportEof
                        }
                        Ok(bytes) => {
                            pending_read = Some(bytes);
                            NextInput::Inbound
                        }
                        Err(failure) => {
                            let cause = read_termination(failure, &mut builder.report.counters);
                            builder.terminate(cause);
                            NextInput::Shutdown
                        }
                    }
                }
            }
            DriverOutput::Event(_) | DriverOutput::StateChanged(_) | DriverOutput::Failure(_) => {
                NextInput::Wake
            }
            DriverOutput::Terminal(_) => break,
        };

        if builder.report.termination == Some(AdapterTermination::CounterOverflow) {
            if shutdown_sent {
                break;
            }
            next = NextInput::Shutdown;
        }
    }

    let _ = stream.shutdown(Shutdown::Both);
    builder.report
}

fn record_poll(builder: &mut ReportBuilder, poll: &PollResult<'_>) -> bool {
    if let Some(command) = &poll.command {
        let observation = match command {
            CommandDisposition::Applied(_) => AdapterObservation::CommandApplied,
            CommandDisposition::Rejected { .. } => AdapterObservation::CommandRejected,
            CommandDisposition::TerminalRejected(_) => AdapterObservation::CommandTerminalRejected,
            CommandDisposition::ProducersDropped => AdapterObservation::ProducersDropped,
        };
        if !builder.observe(observation) {
            return false;
        }
    }
    let observation = match &poll.output {
        DriverOutput::Idle => return true,
        DriverOutput::Write(bytes) => AdapterObservation::WriteOffered { bytes: bytes.len() },
        DriverOutput::Event(event) => AdapterObservation::Event(EventKind::from(event)),
        DriverOutput::StateChanged(state) => AdapterObservation::StateChanged(*state),
        DriverOutput::Failure(failure) => AdapterObservation::Failure {
            state_after: failure.state_after,
        },
        DriverOutput::Terminal(_) => AdapterObservation::Terminal,
    };
    builder.observe(observation)
}

fn read_with_deadline(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    timeout: Duration,
    builder: &mut ReportBuilder,
) -> Result<usize, OperationFailure> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(OperationFailure::Timeout);
        }
        if let Err(error) = stream.set_read_timeout(Some(remaining)) {
            match classify_error(error.kind()) {
                IoDecision::Retry => {
                    if !increment(&mut builder.report.counters.interruptions) {
                        builder.counter_failed();
                        return Err(OperationFailure::Io(SocketErrorKind::Other));
                    }
                    continue;
                }
                IoDecision::Timeout => return Err(OperationFailure::Timeout),
                IoDecision::Fail(kind) => return Err(OperationFailure::Io(kind)),
            }
        }
        if !increment(&mut builder.report.counters.read_calls) {
            builder.counter_failed();
            return Err(OperationFailure::Io(SocketErrorKind::Other));
        }
        match stream.read(buffer) {
            Ok(bytes) => {
                if !add(&mut builder.report.counters.bytes_read, bytes) {
                    builder.counter_failed();
                    return Err(OperationFailure::Io(SocketErrorKind::Other));
                }
                if bytes > 0
                    && bytes < buffer.len()
                    && !increment(&mut builder.report.counters.partial_reads)
                {
                    builder.counter_failed();
                    return Err(OperationFailure::Io(SocketErrorKind::Other));
                }
                return Ok(bytes);
            }
            Err(error) => match classify_error(error.kind()) {
                IoDecision::Retry => {
                    if !increment(&mut builder.report.counters.interruptions) {
                        builder.counter_failed();
                        return Err(OperationFailure::Io(SocketErrorKind::Other));
                    }
                }
                IoDecision::Timeout => return Err(OperationFailure::Timeout),
                IoDecision::Fail(kind) => return Err(OperationFailure::Io(kind)),
            },
        }
    }
}

fn write_with_deadline(
    stream: &mut TcpStream,
    bytes: &[u8],
    timeout: Duration,
    builder: &mut ReportBuilder,
) -> WriteResult {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return WriteResult::Failed(OperationFailure::Timeout);
        }
        if let Err(error) = stream.set_write_timeout(Some(remaining)) {
            match classify_error(error.kind()) {
                IoDecision::Retry => {
                    if !increment(&mut builder.report.counters.interruptions) {
                        builder.counter_failed();
                        return WriteResult::Failed(OperationFailure::Io(SocketErrorKind::Other));
                    }
                    continue;
                }
                IoDecision::Timeout => {
                    return WriteResult::Failed(OperationFailure::Timeout);
                }
                IoDecision::Fail(kind) => {
                    return WriteResult::Failed(OperationFailure::Io(kind));
                }
            }
        }
        if !increment(&mut builder.report.counters.write_calls) {
            builder.counter_failed();
            return WriteResult::Failed(OperationFailure::Io(SocketErrorKind::Other));
        }
        match stream.write(bytes) {
            Ok(0) => return WriteResult::Lost,
            Ok(written) => {
                if !add(&mut builder.report.counters.bytes_written, written) {
                    builder.counter_failed();
                    return WriteResult::Failed(OperationFailure::Io(SocketErrorKind::Other));
                }
                let flush_failure = flush_with_deadline(stream, deadline, builder).err();
                return WriteResult::Progress {
                    bytes: written,
                    flush_failure,
                };
            }
            Err(error) => match classify_error(error.kind()) {
                IoDecision::Retry => {
                    if !increment(&mut builder.report.counters.interruptions) {
                        builder.counter_failed();
                        return WriteResult::Failed(OperationFailure::Io(SocketErrorKind::Other));
                    }
                }
                IoDecision::Timeout => {
                    return WriteResult::Failed(OperationFailure::Timeout);
                }
                IoDecision::Fail(kind) => {
                    return WriteResult::Failed(OperationFailure::Io(kind));
                }
            },
        }
    }
}

fn flush_with_deadline(
    stream: &mut TcpStream,
    deadline: Instant,
    builder: &mut ReportBuilder,
) -> Result<(), OperationFailure> {
    loop {
        if Instant::now() >= deadline {
            return Err(OperationFailure::Timeout);
        }
        if !increment(&mut builder.report.counters.flush_calls) {
            builder.counter_failed();
            return Err(OperationFailure::Io(SocketErrorKind::Other));
        }
        match stream.flush() {
            Ok(()) => return Ok(()),
            Err(error) => match classify_error(error.kind()) {
                IoDecision::Retry => {
                    if !increment(&mut builder.report.counters.interruptions) {
                        builder.counter_failed();
                        return Err(OperationFailure::Io(SocketErrorKind::Other));
                    }
                }
                IoDecision::Timeout => return Err(OperationFailure::Timeout),
                IoDecision::Fail(kind) => return Err(OperationFailure::Io(kind)),
            },
        }
    }
}

fn read_termination(
    failure: OperationFailure,
    counters: &mut AdapterCounters,
) -> AdapterTermination {
    match failure {
        OperationFailure::Timeout => {
            let _ = increment(&mut counters.read_timeouts);
            AdapterTermination::ReadTimeout
        }
        OperationFailure::Io(kind) => AdapterTermination::ReadIo(kind),
    }
}

fn write_termination(
    failure: OperationFailure,
    counters: &mut AdapterCounters,
) -> AdapterTermination {
    match failure {
        OperationFailure::Timeout => {
            let _ = increment(&mut counters.write_timeouts);
            AdapterTermination::WriteTimeout
        }
        OperationFailure::Io(kind) => AdapterTermination::WriteIo(kind),
    }
}

fn classify_error(kind: ErrorKind) -> IoDecision {
    match kind {
        ErrorKind::Interrupted => IoDecision::Retry,
        ErrorKind::TimedOut | ErrorKind::WouldBlock => IoDecision::Timeout,
        ErrorKind::ConnectionRefused => IoDecision::Fail(SocketErrorKind::ConnectionRefused),
        ErrorKind::ConnectionReset => IoDecision::Fail(SocketErrorKind::ConnectionReset),
        ErrorKind::BrokenPipe => IoDecision::Fail(SocketErrorKind::BrokenPipe),
        ErrorKind::NotConnected => IoDecision::Fail(SocketErrorKind::NotConnected),
        _ => IoDecision::Fail(SocketErrorKind::Other),
    }
}

pub(crate) fn socket_error_kind(error: &Error) -> SocketErrorKind {
    match classify_error(error.kind()) {
        IoDecision::Retry => SocketErrorKind::Other,
        IoDecision::Timeout if error.kind() == ErrorKind::WouldBlock => SocketErrorKind::WouldBlock,
        IoDecision::Timeout => SocketErrorKind::TimedOut,
        IoDecision::Fail(kind) => kind,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupted_is_the_only_retry_class() {
        assert_eq!(classify_error(ErrorKind::Interrupted), IoDecision::Retry);
        assert_eq!(classify_error(ErrorKind::TimedOut), IoDecision::Timeout);
        assert_eq!(classify_error(ErrorKind::WouldBlock), IoDecision::Timeout);
    }

    #[test]
    fn report_reserves_its_last_slot_for_a_typed_limit() {
        let mut report = ReportBuilder::connected(Role::Server, 2);
        assert!(report.observe(AdapterObservation::TransportEof));
        assert!(!report.observe(AdapterObservation::Shutdown));
        assert_eq!(report.report.observations.len(), 2);
        assert_eq!(
            report.report.observations[1],
            AdapterObservation::AdapterFailure(AdapterTermination::ReportLimit)
        );
    }
}
