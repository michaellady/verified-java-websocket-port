use std::collections::VecDeque;

use websocket_core::{
    ConnectionState, CoreOutput, SemanticEvent, TransportWrite, TypedProtocolFailure,
};

use crate::DriverOutput;

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
        std::mem::take(&mut self.flush_due)
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
