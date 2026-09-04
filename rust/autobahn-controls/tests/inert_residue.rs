//! Residue probes for the negative control's drain loop.
//!
//! `drain` is the WHOLE behaviour of the empty/stub control: it reads and
//! discards, writes nothing, and ends on a budget rather than on a protocol
//! event. The round-4 US-019 sweep never swept Rust; sweeping it found that
//! the loop's two bounding conjuncts and two of its four read arms survived
//! neutralisation, so the properties the module's own doc comments state
//! ("bounded twice over", "the peer hung up") were asserted by nothing.
//!
//! Every test drives the control over LOOPBACK with a raw `TcpStream` as the
//! peer, and every one of them is bounded by the control's own
//! [`InertBounds`], which each test states explicitly.

use std::io::Write;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use autobahn_controls::inert::{InertBounds, serve_inert_once};

/// One read attempt costs `read_timeout` when the peer is silent, which is
/// the only cost a DRAINING session pays. A budget is therefore stated here
/// as the wall-clock window it buys and converted through that one cost,
/// rather than chosen as a magnitude (shape C of `make -C rust
/// fixture-guard`; the same idiom as `polls_for` in `negative_control.rs`).
fn reads_for(window: Duration, read_timeout: Duration) -> u32 {
    let per_read = read_timeout.max(Duration::from_micros(1));
    let reads = window.as_micros() / per_read.as_micros();
    u32::try_from(reads).unwrap_or(u32::MAX).max(1)
}

const READ_TIMEOUT: Duration = Duration::from_millis(2);

/// Serves ONE inert session on a fresh loopback listener and hands back the
/// address so the test can be the peer.
fn serve_once(
    bounds: InertBounds,
) -> (
    std::net::SocketAddr,
    thread::JoinHandle<autobahn_controls::InertSession>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let address = listener.local_addr().expect("bound address");
    let handle = thread::spawn(move || serve_inert_once(&listener, &bounds).expect("inert accept"));
    (address, handle)
}

// ---------------------------------------------------------------------------
// inert.rs:124 — the EOF arm.
// ---------------------------------------------------------------------------

#[test]
fn the_drain_records_the_peers_eof_and_stops_there() {
    // `Ok(0)` from read(2) is the peer hanging up, and it is the ONLY
    // condition that ends a session early. Without this arm a zero-length
    // read is counted as a read of zero bytes and the loop spins on a dead
    // socket until its budget runs out, so `peer_eof` — the field the
    // control publishes to say the peer left first — is never true.
    let bounds = InertBounds {
        read_timeout: READ_TIMEOUT,
        linger: Duration::from_secs(2),
        max_reads: reads_for(Duration::from_secs(2), READ_TIMEOUT),
        read_buffer: 4096,
    };
    let budget = bounds.max_reads;
    let (address, control) = serve_once(bounds);
    let mut peer = TcpStream::connect(address).expect("connect to the control");
    peer.write_all(b"GET /runCase HTTP/1.1\r\n\r\n")
        .expect("write");
    peer.shutdown(Shutdown::Both).expect("peer hangs up");
    let session = control.join().expect("control thread");

    assert!(
        session.peer_eof,
        "the control must record that the PEER ended the session; without the EOF arm a \
         hung-up socket is read as a zero-byte read forever. reads={} of budget {budget}",
        session.reads
    );
    assert!(
        session.reads < budget,
        "the session must have ended on the peer's EOF, not by exhausting its read budget; \
         reads={} budget={budget}",
        session.reads
    );
    assert_eq!(
        session.bytes_written, 0,
        "the control answers nothing, ever"
    );
}

// ---------------------------------------------------------------------------
// inert.rs:121 — the two conjuncts that bound the loop.
// ---------------------------------------------------------------------------

#[test]
fn the_drain_stops_at_its_read_budget_even_while_the_peer_holds_the_socket_open() {
    // `session.reads < bounds.max_reads`. The peer below never sends and
    // never closes, so EOF cannot end the session and the linger is set far
    // beyond the read budget: the ONLY thing that can stop this loop is the
    // read count.
    let bounds = InertBounds {
        read_timeout: READ_TIMEOUT,
        linger: Duration::from_secs(5),
        max_reads: 8,
        read_buffer: 4096,
    };
    let (address, control) = serve_once(bounds);
    let peer = TcpStream::connect(address).expect("connect to the control");
    let session = control.join().expect("control thread");
    // The peer is dropped only AFTER the control has finished, so nothing
    // the peer does can be what ended the session.
    drop(peer);

    assert!(
        !session.peer_eof,
        "the peer held the socket open for the whole session; an EOF here means the probe \
         is stale, not that the budget worked"
    );
    assert_eq!(
        session.reads, 8,
        "the read budget must be what ends a session whose peer neither speaks nor hangs \
         up; without it the session runs to the 5s linger instead"
    );
}

#[test]
fn the_drain_stops_at_its_linger_deadline_even_with_read_budget_left() {
    // `Instant::now() < deadline`. The read budget here buys ten times the
    // linger, so a session that ended on the count rather than the clock
    // would have to spend the whole budget first.
    let linger = Duration::from_millis(100);
    let bounds = InertBounds {
        read_timeout: READ_TIMEOUT,
        linger,
        max_reads: reads_for(linger * 10, READ_TIMEOUT),
        read_buffer: 4096,
    };
    let budget = bounds.max_reads;
    let (address, control) = serve_once(bounds);
    let peer = TcpStream::connect(address).expect("connect to the control");
    let started = Instant::now();
    let session = control.join().expect("control thread");
    let elapsed = started.elapsed();
    drop(peer);

    assert!(
        !session.peer_eof,
        "the peer held the socket open; an EOF here means the probe is stale"
    );
    assert!(
        session.reads < budget,
        "the wall-clock deadline must end a session before its read budget does, or a \
         control whose peer stalls has no time bound at all. reads={} budget={budget} \
         elapsed={elapsed:?}",
        session.reads
    );
}

// ---------------------------------------------------------------------------
// inert.rs:129 — the retryable-error arm.
// ---------------------------------------------------------------------------

#[test]
fn a_read_timeout_does_not_end_the_drain_the_way_a_real_error_does() {
    // `Err(error) if retryable(error.kind()) => {}`. A silent peer makes
    // every read time out, and a timeout means "nothing yet", not "the
    // transport is gone". Without this arm the very first timed-out read
    // falls through to `Err(_) => break` and the control stops draining
    // before the peer has said anything — so a peer that pauses before
    // sending its upgrade request is never read at all.
    let bounds = InertBounds {
        read_timeout: READ_TIMEOUT,
        linger: Duration::from_secs(2),
        max_reads: reads_for(Duration::from_secs(2), READ_TIMEOUT),
        read_buffer: 4096,
    };
    let (address, control) = serve_once(bounds);
    let mut peer = TcpStream::connect(address).expect("connect to the control");
    // Stay silent across many read timeouts, then speak.
    thread::sleep(READ_TIMEOUT * 25);
    peer.write_all(b"GET /runCase HTTP/1.1\r\n\r\n")
        .expect("write");
    peer.shutdown(Shutdown::Both).expect("peer hangs up");
    let session = control.join().expect("control thread");

    assert!(
        session.bytes_read > 0,
        "the control must still be draining after an idle period: a read timeout is \
         'nothing yet', and treating it as a transport failure loses every byte the peer \
         sends after any pause. reads={} peer_eof={}",
        session.reads,
        session.peer_eof
    );
    assert!(
        session.peer_eof,
        "and it must still see the peer's EOF afterwards"
    );
}
