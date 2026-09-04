//! Fixed-capacity queue used for the AC4 bounded event and write queues.
//!
//! Capacity is fixed at construction from a [`crate::config::ConnectionConfig`]
//! limit; a full queue refuses the push (the caller surfaces
//! [`crate::error::FailureCode::Backpressure`]) instead of growing. The
//! backing `VecDeque` is allocated once with the full capacity, and the
//! length guard guarantees it never reallocates.

use std::collections::VecDeque;

/// A bounded FIFO queue that never grows past its construction capacity.
#[derive(Debug)]
pub(crate) struct BoundedQueue<T> {
    items: VecDeque<T>,
    capacity: usize,
}

impl<T> BoundedQueue<T> {
    /// A queue with the given fixed capacity (allocated once, up front).
    pub(crate) fn new(capacity: usize) -> Self {
        BoundedQueue {
            items: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Free slots remaining.
    pub(crate) fn available(&self) -> usize {
        self.capacity - self.items.len()
    }

    /// Push at the back. The caller must have checked [`Self::available`];
    /// this returns `false` (and drops nothing, refusing the item back via
    /// the `Err`) when full, so an unchecked push can never grow the queue.
    pub(crate) fn push(&mut self, item: T) -> Result<(), T> {
        if self.items.len() >= self.capacity {
            return Err(item);
        }
        self.items.push_back(item);
        Ok(())
    }

    /// Pop from the front (FIFO).
    pub(crate) fn pop(&mut self) -> Option<T> {
        self.items.pop_front()
    }
}
