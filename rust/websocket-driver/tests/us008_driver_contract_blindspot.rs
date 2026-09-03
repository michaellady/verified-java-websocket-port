//! US-008 suite-calibration blind spot: terminal never precedes a disposition.
//!
//! NEW in US-008. `driver_contract` asserts that accepted commands are
//! terminal-rejected before the single terminal, but every existing scenario
//! reaches terminal through `poll` paths that suppress the terminal whenever a
//! disposition is produced in the same turn. The `WriteProgress` path has no
//! such guard, so a ledger that delivered the terminal while dispositions were
//! still queued survived the whole workspace.

#![forbid(unsafe_code)]

use websocket_core::{ConnectionConfig, ConnectionLimits, LocalCommand, Role};
use websocket_driver::{CommandDisposition, DriverInput, DriverOutput, connection_driver};

#[test]
fn no_disposition_is_delivered_after_the_single_terminal() {
    let config = ConnectionConfig::try_from(ConnectionLimits::default()).expect("default limits");
    let (handle, mut owner) = connection_driver(config, Role::Server);
    for _ in 0..3 {
        handle
            .try_enqueue(LocalCommand::SendPing {
                payload: vec![].try_into().expect("payload"),
                mask_key: None,
            })
            .expect("within the entry bound");
    }

    let script = [
        DriverInput::Shutdown,
        DriverInput::Wake,
        // The WriteProgress path pops a disposition and then asks the ledger
        // for the next output without the poll-level terminal guard.
        DriverInput::WriteProgress { bytes: 0 },
        DriverInput::WriteProgress { bytes: 0 },
        DriverInput::Wake,
        DriverInput::Wake,
        DriverInput::Wake,
    ];

    let mut terminals = 0_usize;
    let mut dispositions = 0_usize;
    let mut terminal_seen_in_earlier_poll = false;
    for (turn, input) in script.into_iter().enumerate() {
        let result = owner.poll(input);
        let terminal_now = matches!(result.output, DriverOutput::Terminal(_));
        if let Some(command) = &result.command {
            dispositions += 1;
            assert!(
                !terminal_seen_in_earlier_poll,
                "turn {turn}: {command:?} was delivered after the terminal"
            );
            assert!(matches!(
                command,
                CommandDisposition::TerminalRejected(_) | CommandDisposition::ProducersDropped
            ));
        }
        if terminal_now {
            terminals += 1;
        }
        terminal_seen_in_earlier_poll |= terminal_now;
    }

    assert_eq!(terminals, 1, "exactly one terminal delivery");
    assert_eq!(dispositions, 3, "every accepted command is disposed once");
}
