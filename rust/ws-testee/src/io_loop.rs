//! The one bounded blocking I/O loop both adapters share (US-018).
//!
//! Owns exactly the transport concerns: partial reads with a timeout,
//! partial writes reported back as [`ws_driver::DriverInput::WriteProgress`],
//! EOF and socket-error normalization, and a hard poll budget so no run can
//! spin forever. Protocol truth lives in the core; message-level policy
//! (echo, scripted sends, close initiation) is injected as an adapter
//! policy over the drained events.

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use ws_core::{CloseDetail, CommandSender, ReadyState, SemanticEvent, TypedProtocolFailure};
use ws_driver::{ConnectionDriver, DriverInput, DriverOutput, InputDisposition};

/// Bounded I/O parameters (US-018 AC1: bounded I/O buffers and explicit
/// timeouts; deterministic defaults for the fixtures).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoBounds {
    /// Read buffer size in bytes.
    pub read_buffer: usize,
    /// Socket read timeout per attempt.
    pub read_timeout: Duration,
    /// Largest number of bytes handed to one socket write call (forces
    /// partial-write reporting when smaller than a frame).
    pub write_chunk: usize,
    /// Socket write timeout per attempt (`SO_SNDTIMEO`): a write that
    /// cannot place a single byte within this window returns a retryable
    /// timeout instead of blocking the adapter inside the syscall.
    pub write_timeout: Duration,
    /// Absolute no-progress write deadline: once a write output makes no
    /// byte progress for this long (a peer that stopped reading after the
    /// kernel socket buffers filled), the run ends with the typed
    /// [`LoopOutcome::WriteStalled`] outcome.
    ///
    /// Java-fidelity note: shipped Java has NO socket-layer write deadline
    /// (`WebSocketClient.WebsocketWriteThread` blocks in `ostream.write()`
    /// indefinitely; `Socket#setSoTimeout` bounds reads only) — its only
    /// liveness bound is the adapter-layer `connectionLostTimeout`
    /// keepalive above the ported core. This deadline is US-018 adapter
    /// SAFETY policy (AC2 bounded write resources), a disclosed
    /// divergence, never core protocol.
    pub write_stall_limit: Duration,
    /// Hard budget of driver polls before the loop reports exhaustion.
    pub max_polls: u64,
}

impl Default for IoBounds {
    fn default() -> IoBounds {
        IoBounds {
            read_buffer: 4096,
            read_timeout: Duration::from_millis(25),
            write_chunk: 4096,
            write_timeout: Duration::from_millis(25),
            write_stall_limit: Duration::from_secs(2),
            max_polls: 200_000,
        }
    }
}

/// How one adapter run ended (normalized result vocabulary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoopOutcome {
    /// The driver delivered its exactly-once terminal outcome.
    Terminal,
    /// The core reported a fatal typed failure; the adapter shut the
    /// socket down and stopped.
    ProtocolFailure(TypedProtocolFailure),
    /// The socket failed with the named normalized error kind.
    SocketError(String),
    /// A write made no byte progress for the whole
    /// [`IoBounds::write_stall_limit`] window (peer stopped reading and the
    /// kernel socket buffers are exhausted); the adapter shut the socket
    /// down instead of blocking forever.
    WriteStalled,
    /// The poll budget ran out before a terminal outcome.
    BudgetExhausted,
}

/// What one adapter run observed (adapter-side accounting only; every
/// protocol observable inside comes verbatim from the core's streams).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionReport {
    /// How the run ended.
    pub outcome: LoopOutcome,
    /// Delivered text messages, in order.
    pub texts: Vec<String>,
    /// Delivered binary messages, in order.
    pub binaries: Vec<Vec<u8>>,
    /// Ping payloads observed.
    pub pings: Vec<Vec<u8>>,
    /// Pong payloads observed.
    pub pongs: Vec<Vec<u8>>,
    /// The governing close detail at the end, if any.
    pub close: Option<CloseDetail>,
    /// Total driver polls spent.
    pub polls: u64,
    /// Terminal deliveries observed (the exactly-once property makes any
    /// value other than one a contract violation worth reporting).
    pub terminals: u64,
}

impl ConnectionReport {
    /// One deterministic summary line for the CLI harness.
    #[must_use]
    pub fn summary(&self) -> String {
        let close = self.close.as_ref().map_or_else(
            || "none".to_owned(),
            |detail| format!("{}:{}", detail.code, detail.origin.wire_name()),
        );
        format!(
            "outcome={:?} texts={} binaries={} pings={} pongs={} close={} terminals={}",
            self.outcome,
            self.texts.len(),
            self.binaries.len(),
            self.pings.len(),
            self.pongs.len(),
            close,
            self.terminals,
        )
    }

    /// Whether the run ended with the exactly-once terminal outcome.
    #[must_use]
    pub fn clean(&self) -> bool {
        self.outcome == LoopOutcome::Terminal && self.terminals == 1
    }
}

/// Adapter-side message policy over drained events (echoing, scripted
/// sends). Runs OUTSIDE the core: it may only enqueue commands through the
/// bounded sender, never touch protocol state.
pub trait EventPolicy {
    /// Observe one drained semantic event; enqueue follow-up commands
    /// through `sender` as needed.
    fn on_event(&mut self, event: &SemanticEvent, sender: &CommandSender);
}

/// A policy that does nothing (pure observer).
#[derive(Debug, Default, Clone, Copy)]
pub struct ObserveOnly;

impl EventPolicy for ObserveOnly {
    fn on_event(&mut self, _event: &SemanticEvent, _sender: &CommandSender) {}
}

/// Drives one established socket to its terminal outcome through the
/// single-owner driver. `sender` is the same bounded handle producers use;
/// the policy enqueues through it. Accounting accumulates into the passed
/// report (the fixtures seed it with their handshake-phase polls).
pub fn drive_connection(
    driver: &mut ConnectionDriver,
    sender: &CommandSender,
    stream: &mut TcpStream,
    bounds: &IoBounds,
    policy: &mut dyn EventPolicy,
    report: &mut ConnectionReport,
) {
    report.outcome = LoopOutcome::BudgetExhausted;
    let _ = stream.set_read_timeout(Some(bounds.read_timeout));
    let _ = stream.set_write_timeout(Some(bounds.write_timeout.max(Duration::from_millis(1))));
    let mut read_buffer = vec![0u8; bounds.read_buffer.max(1)];
    let mut pending_chunk: Vec<u8> = Vec::new();
    let mut eof_seen = false;
    let mut write_stall = WriteStallClock::new(bounds.write_stall_limit);

    while report.polls < bounds.max_polls {
        // 1. Give the driver a turn and drain one output.
        let step = if pending_chunk.is_empty() {
            pump(driver, DriverInput::Wake, report)
        } else {
            let chunk = std::mem::take(&mut pending_chunk);
            let step = pump(driver, DriverInput::Inbound(&chunk), report);
            if matches!(step.input, InputDisposition::Deferred(_)) {
                // The driver did not consume the bytes; retry the identical
                // chunk after this output is handled.
                pending_chunk = chunk;
            }
            step
        };
        match step.output {
            StepOutput::Write(bytes) => {
                let take = bytes.len().min(bounds.write_chunk.max(1));
                match stream.write(&bytes[..take]) {
                    Ok(written) if written > 0 => {
                        write_stall.progressed();
                        let _ = pump(
                            driver,
                            DriverInput::WriteProgress { bytes: written },
                            report,
                        );
                    }
                    Ok(_) => {}
                    Err(error) if retryable(error.kind()) => {
                        // No byte progressed: a peer that stopped reading
                        // (kernel buffers exhausted) must not block the
                        // adapter forever — the bounded write deadline
                        // converts a persistent stall into the typed
                        // outcome (adapter safety policy; see IoBounds).
                        if write_stall.stalled() {
                            let _ = pump(driver, DriverInput::Shutdown, report);
                            report.outcome = LoopOutcome::WriteStalled;
                            let _ = stream.shutdown(std::net::Shutdown::Both);
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = pump(driver, DriverInput::Shutdown, report);
                        report.outcome = LoopOutcome::SocketError(format!("{:?}", error.kind()));
                        break;
                    }
                }
                continue;
            }
            StepOutput::Event(event) => {
                record_event(&event, report);
                policy.on_event(&event, sender);
                continue;
            }
            StepOutput::Failure(failure) => {
                report.outcome = LoopOutcome::ProtocolFailure(failure);
                let _ = stream.shutdown(std::net::Shutdown::Both);
                break;
            }
            StepOutput::Terminal => {
                report.terminals += 1;
                report.outcome = LoopOutcome::Terminal;
                break;
            }
            StepOutput::Idle => {}
        }
        // 2. Idle: look for transport facts.
        if eof_seen || !pending_chunk.is_empty() {
            continue;
        }
        match stream.read(&mut read_buffer) {
            Ok(0) => {
                eof_seen = true;
                let _ = pump(driver, DriverInput::TransportEof, report);
            }
            Ok(n) => pending_chunk = read_buffer[..n].to_vec(),
            Err(error) if retryable(error.kind()) => {}
            Err(error) => {
                let _ = pump(driver, DriverInput::Shutdown, report);
                report.outcome = LoopOutcome::SocketError(format!("{:?}", error.kind()));
                break;
            }
        }
    }
    report.close = driver.close_detail().cloned();
}

fn retryable(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
    )
}

/// Tracks byte progress across write attempts: the deadline arms on the
/// first no-progress attempt and disarms on any successful byte.
struct WriteStallClock {
    limit: Duration,
    stalled_since: Option<Instant>,
}

impl WriteStallClock {
    fn new(limit: Duration) -> WriteStallClock {
        WriteStallClock {
            limit,
            stalled_since: None,
        }
    }

    /// A write placed at least one byte: disarm the deadline.
    fn progressed(&mut self) {
        self.stalled_since = None;
    }

    /// A write attempt made no progress; returns whether the no-progress
    /// window has now exceeded the limit.
    fn stalled(&mut self) -> bool {
        let since = *self.stalled_since.get_or_insert_with(Instant::now);
        since.elapsed() >= self.limit
    }
}

/// One pumped poll, with the borrowed write suffix copied out so the
/// caller can hand it to the socket without holding the driver borrow.
struct PumpStep {
    input: InputDisposition,
    output: StepOutput,
}

enum StepOutput {
    Idle,
    Write(Vec<u8>),
    Event(SemanticEvent),
    Failure(TypedProtocolFailure),
    Terminal,
}

fn pump(
    driver: &mut ConnectionDriver,
    input: DriverInput<'_>,
    report: &mut ConnectionReport,
) -> PumpStep {
    report.polls += 1;
    let result = driver.poll(input);
    let output = match result.output {
        DriverOutput::Idle => StepOutput::Idle,
        DriverOutput::Write(suffix) => StepOutput::Write(suffix.to_vec()),
        DriverOutput::Event(event) => StepOutput::Event(event),
        DriverOutput::Failure(failure) => StepOutput::Failure(failure),
        DriverOutput::Terminal(_) => StepOutput::Terminal,
    };
    PumpStep {
        input: result.input,
        output,
    }
}

fn record_event(event: &SemanticEvent, report: &mut ConnectionReport) {
    use ws_core::SemanticEventKind as Kind;
    match &event.kind {
        Kind::Text { text } => report.texts.push(text.clone()),
        Kind::Binary { data } => report.binaries.push(data.clone()),
        Kind::Ping { data } => report.pings.push(data.clone()),
        Kind::Pong { data } => report.pongs.push(data.clone()),
        _ => {}
    }
}

/// Wait until the driver leaves `NotYetConnected` (handshake completion)
/// or a failure/budget stop occurs; used by both fixtures before their
/// message scripts. Returns whether the connection opened.
pub fn drive_until_open(
    driver: &mut ConnectionDriver,
    stream: &mut TcpStream,
    bounds: &IoBounds,
    report: &mut ConnectionReport,
) -> bool {
    let _ = stream.set_read_timeout(Some(bounds.read_timeout));
    let _ = stream.set_write_timeout(Some(bounds.write_timeout.max(Duration::from_millis(1))));
    let mut read_buffer = vec![0u8; bounds.read_buffer.max(1)];
    let mut write_stall = WriteStallClock::new(bounds.write_stall_limit);
    while report.polls < bounds.max_polls {
        if driver.state() != ReadyState::NotYetConnected {
            return true;
        }
        let step = pump(driver, DriverInput::Wake, report);
        match step.output {
            StepOutput::Write(bytes) => {
                let take = bytes.len().min(bounds.write_chunk.max(1));
                match stream.write(&bytes[..take]) {
                    Ok(written) if written > 0 => {
                        write_stall.progressed();
                        let _ = pump(
                            driver,
                            DriverInput::WriteProgress { bytes: written },
                            report,
                        );
                    }
                    Ok(_) => {}
                    Err(error) if retryable(error.kind()) => {
                        // Same bounded-write policy as the connected pump:
                        // a handshake-phase peer that stopped reading must
                        // not wedge the adapter inside a blocking write.
                        if write_stall.stalled() {
                            report.outcome = LoopOutcome::WriteStalled;
                            let _ = stream.shutdown(std::net::Shutdown::Both);
                            return false;
                        }
                    }
                    Err(error) => {
                        report.outcome = LoopOutcome::SocketError(format!("{:?}", error.kind()));
                        return false;
                    }
                }
                continue;
            }
            StepOutput::Failure(failure) => {
                report.outcome = LoopOutcome::ProtocolFailure(failure);
                return false;
            }
            StepOutput::Event(_) | StepOutput::Terminal | StepOutput::Idle => {}
        }
        match stream.read(&mut read_buffer) {
            Ok(0) => {
                let _ = pump(driver, DriverInput::TransportEof, report);
                return false;
            }
            Ok(n) => {
                let chunk = read_buffer[..n].to_vec();
                loop {
                    let step = pump(driver, DriverInput::Inbound(&chunk), report);
                    match step.input {
                        InputDisposition::Consumed { .. } => break,
                        InputDisposition::Deferred(_) => {
                            if report.polls >= bounds.max_polls {
                                return false;
                            }
                        }
                        InputDisposition::Rejected(_) => return false,
                    }
                }
            }
            Err(error) if retryable(error.kind()) => {}
            Err(error) => {
                report.outcome = LoopOutcome::SocketError(format!("{:?}", error.kind()));
                return false;
            }
        }
    }
    false
}

/// A fresh empty report for the fixtures.
#[must_use]
pub fn empty_report() -> ConnectionReport {
    ConnectionReport {
        outcome: LoopOutcome::BudgetExhausted,
        texts: Vec::new(),
        binaries: Vec::new(),
        pings: Vec::new(),
        pongs: Vec::new(),
        close: None,
        polls: 0,
        terminals: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupted_and_timeout_kinds_are_retryable_hard_errors_are_not() {
        // EINTR classification (US-018 AC2): interrupted system calls are
        // retried, never treated as transport loss. Native signal-driven
        // EINTR injection remains a disclosed nonclaim; this pins the
        // classification the retry path runs on.
        assert!(retryable(ErrorKind::Interrupted));
        assert!(retryable(ErrorKind::WouldBlock));
        assert!(retryable(ErrorKind::TimedOut));
        assert!(!retryable(ErrorKind::ConnectionReset));
        assert!(!retryable(ErrorKind::BrokenPipe));
        assert!(!retryable(ErrorKind::UnexpectedEof));
    }

    #[test]
    fn write_stall_clock_arms_on_no_progress_and_disarms_on_bytes() {
        let mut clock = WriteStallClock::new(Duration::from_millis(20));
        assert!(
            !clock.stalled(),
            "first no-progress attempt arms, not fires"
        );
        std::thread::sleep(Duration::from_millis(25));
        assert!(clock.stalled(), "limit exceeded with no progress fires");
        clock.progressed();
        assert!(!clock.stalled(), "byte progress disarms the deadline");
    }

    #[test]
    fn write_stall_clock_zero_limit_fires_immediately() {
        let mut clock = WriteStallClock::new(Duration::ZERO);
        assert!(clock.stalled());
    }
}
