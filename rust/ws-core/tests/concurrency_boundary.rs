//! US-009 AC4 tests: the single mutable owner plus a bounded multi-producer
//! command channel are the ONLY concurrency boundary.
//!
//! The core itself is single-owner by construction (`&mut self` on `handle`,
//! no interior mutability); `CommandQueue`/`CommandSender` form the bounded
//! MPSC handle whose capacity is `command_queue_capacity`. Producers get an
//! explicit typed refusal when full; nothing blocks, nothing allocates
//! unboundedly. Loom-style exploration of this type is classified as
//! systematic testing, not proof (US-006 AC5).
//!
//! Tests may use threads; the core crate may not (see sans_io_contract.rs).

use std::thread;

use ws_core::config::ConnectionConfig;
use ws_core::connection::{CommandQueue, LocalCommand};

fn config_with_capacity(capacity: u64) -> ConnectionConfig {
    ConnectionConfig::builder()
        .command_queue_capacity(capacity)
        .build()
        .expect("valid test config")
}

fn tagged(tag: &str) -> LocalCommand {
    LocalCommand::SendText {
        text: tag.to_owned(),
    }
}

fn tag_of(command: &LocalCommand) -> String {
    match command {
        LocalCommand::SendText { text } => text.clone(),
        other => panic!("unexpected command {other:?}"),
    }
}

#[test]
fn capacity_is_honored_and_refusal_returns_the_command() {
    let config = config_with_capacity(2);
    let (mut queue, sender) = CommandQueue::new(&config);
    assert_eq!(queue.capacity(), 2);
    assert!(sender.try_send(tagged("a")).is_ok());
    assert!(sender.try_send(tagged("b")).is_ok());
    let refused = sender
        .try_send(tagged("c"))
        .expect_err("third send must be refused at capacity 2");
    // The refused command comes back to the producer intact: explicit
    // backpressure, no silent drop, no unbounded growth.
    assert_eq!(tag_of(&refused.command), "c");
    assert_eq!(queue.len(), 2);
    // Draining frees capacity for the retry.
    assert_eq!(tag_of(&queue.pop().expect("queued")), "a");
    assert!(sender.try_send(tagged("c")).is_ok());
    assert_eq!(tag_of(&queue.pop().expect("queued")), "b");
    assert_eq!(tag_of(&queue.pop().expect("queued")), "c");
    assert!(queue.pop().is_none());
    assert!(queue.is_empty());
}

#[test]
fn single_threaded_interleaving_preserves_total_fifo_order() {
    let config = config_with_capacity(8);
    let (mut queue, sender_a) = CommandQueue::new(&config);
    let sender_b = sender_a.clone();
    // Two producers interleaved deterministically: the drained order is the
    // send order (total FIFO implies FIFO per producer).
    assert!(sender_a.try_send(tagged("a1")).is_ok());
    assert!(sender_b.try_send(tagged("b1")).is_ok());
    assert!(sender_a.try_send(tagged("a2")).is_ok());
    assert!(sender_b.try_send(tagged("b2")).is_ok());
    let drained: Vec<String> = std::iter::from_fn(|| queue.pop())
        .map(|c| tag_of(&c))
        .collect();
    assert_eq!(drained, ["a1", "b1", "a2", "b2"]);
}

#[test]
fn multi_producer_threads_never_exceed_capacity_and_keep_per_producer_fifo() {
    let capacity = 8u64;
    let producers = 4usize;
    let attempts = 50usize;
    let config = config_with_capacity(capacity);
    let (mut queue, sender) = CommandQueue::new(&config);
    let handles: Vec<_> = (0..producers)
        .map(|producer| {
            let sender = sender.clone();
            thread::spawn(move || {
                let mut accepted = Vec::new();
                for seq in 0..attempts {
                    let tag = format!("p{producer}-{seq}");
                    if sender.try_send(tagged(&tag)).is_ok() {
                        accepted.push(tag);
                    }
                    // try_send never blocks: a refusal returns immediately
                    // and the producer decides what to do (here: drop).
                }
                accepted
            })
        })
        .collect();
    let accepted_per_producer: Vec<Vec<String>> = handles
        .into_iter()
        .map(|h| h.join().expect("producer thread must not panic"))
        .collect();
    // The queue never grew beyond its bound.
    assert!(queue.len() <= capacity as usize);
    let drained: Vec<String> = std::iter::from_fn(|| queue.pop())
        .map(|c| tag_of(&c))
        .collect();
    assert!(drained.len() <= capacity as usize);
    // Everything drained was genuinely accepted, and per-producer relative
    // order in the drain matches that producer's send order (FIFO per
    // producer; the total order across producers is scheduler-chosen).
    for (producer, accepted) in accepted_per_producer.iter().enumerate() {
        let drained_for_producer: Vec<&String> = drained
            .iter()
            .filter(|tag| tag.starts_with(&format!("p{producer}-")))
            .collect();
        let accepted_prefix: Vec<&String> =
            accepted.iter().take(drained_for_producer.len()).collect();
        assert_eq!(
            drained_for_producer, accepted_prefix,
            "producer {producer} FIFO order"
        );
    }
}

#[test]
fn owner_drains_the_channel_into_the_core_it_exclusively_owns() {
    // The intended topology: N producers -> bounded channel -> ONE owner that
    // holds `&mut ConnectionCore` and feeds it. The core never sees the
    // channel; the owner is the only writer. (Driven-concurrency behavior is
    // US-017; this pins the contract shape.)
    use ws_core::connection::{ConnectionCore, InitialState, Input, Role};
    let config = ConnectionConfig::default();
    let (mut queue, sender) = CommandQueue::new(&config);
    let mut core = ConnectionCore::new_in_state(config, Role::Server, InitialState::Closing);
    assert!(sender.try_send(tagged("only")).is_ok());
    drop(sender);
    let mut outcomes = Vec::new();
    while let Some(command) = queue.pop() {
        outcomes.push(core.handle(Input::Command(command)));
    }
    // In Closing state the command is refused by the Q26 state gate --
    // deterministically, through the single owner.
    assert_eq!(outcomes.len(), 1);
    assert_eq!(
        outcomes[0]
            .as_ref()
            .expect_err("closing refuses sends")
            .code,
        ws_core::error::FailureCode::StateViolation
    );
}
