------------------------------ MODULE ConnectionModel ------------------------------
EXTENDS Naturals, Sequences, FiniteSets

States == {"Connecting", "Open", "Closing", "Closed"}
MaxCommands == 2
MaxWrites == 2
MaxEvents == 2

VARIABLES state, commandQ, writeQ, eventQ, shutdownRequested,
          terminalQueued, terminalDelivered, backpressureCount

vars == <<state, commandQ, writeQ, eventQ, shutdownRequested,
          terminalQueued, terminalDelivered, backpressureCount>>

Init ==
    /\ state = "Connecting"
    /\ commandQ = <<>>
    /\ writeQ = <<>>
    /\ eventQ = <<>>
    /\ shutdownRequested = FALSE
    /\ terminalQueued = FALSE
    /\ terminalDelivered = FALSE
    /\ backpressureCount = 0

CompleteHandshake ==
    /\ state = "Connecting"
    /\ state' = "Open"
    /\ UNCHANGED <<commandQ, writeQ, eventQ, shutdownRequested,
                   terminalQueued, terminalDelivered, backpressureCount>>

EnqueueCommand ==
    /\ state \in {"Open", "Closing"}
    /\ Len(commandQ) < MaxCommands
    /\ commandQ' = Append(commandQ, "command")
    /\ UNCHANGED <<state, writeQ, eventQ, shutdownRequested,
                   terminalQueued, terminalDelivered, backpressureCount>>

ReceiveFrame ==
    /\ state = "Open"
    /\ Len(eventQ) < MaxEvents
    /\ eventQ' = Append(eventQ, "event")
    /\ UNCHANGED <<state, commandQ, writeQ, shutdownRequested,
                   terminalQueued, terminalDelivered, backpressureCount>>

ReceiveClose ==
    /\ state \in {"Open", "Closing"}
    /\ Len(eventQ) < MaxEvents
    /\ state' = "Closing"
    /\ eventQ' = Append(eventQ, "terminal")
    /\ terminalQueued' = TRUE
    /\ UNCHANGED <<commandQ, writeQ, shutdownRequested,
                   terminalDelivered, backpressureCount>>

FlushOutbound ==
    /\ Len(writeQ) > 0
    /\ writeQ' = Tail(writeQ)
    /\ UNCHANGED <<state, commandQ, eventQ, shutdownRequested,
                   terminalQueued, terminalDelivered, backpressureCount>>

BeginShutdown ==
    /\ shutdownRequested = FALSE
    /\ state \in {"Connecting", "Open", "Closing"}
    /\ shutdownRequested' = TRUE
    /\ state' = "Closing"
    /\ UNCHANGED <<commandQ, writeQ, eventQ, terminalQueued,
                   terminalDelivered, backpressureCount>>

DeliverCallback ==
    /\ Len(eventQ) > 0
    /\ eventQ' = Tail(eventQ)
    /\ terminalDelivered' = terminalDelivered \/ (Head(eventQ) = "terminal")
    /\ UNCHANGED <<state, commandQ, writeQ, shutdownRequested,
                   terminalQueued, backpressureCount>>

ApplyBackpressure ==
    /\ Len(commandQ) = MaxCommands \/ Len(writeQ) = MaxWrites \/ Len(eventQ) = MaxEvents
    /\ backpressureCount' = backpressureCount + 1
    /\ UNCHANGED <<state, commandQ, writeQ, eventQ, shutdownRequested,
                   terminalQueued, terminalDelivered>>

FinishClose ==
    /\ state = "Closing"
    /\ Len(commandQ) = 0
    /\ Len(writeQ) = 0
    /\ (~terminalQueued \/ terminalDelivered)
    /\ state' = "Closed"
    /\ UNCHANGED <<commandQ, writeQ, eventQ, shutdownRequested,
                   terminalQueued, terminalDelivered, backpressureCount>>

Next ==
    \/ CompleteHandshake
    \/ EnqueueCommand
    \/ ReceiveFrame
    \/ ReceiveClose
    \/ FlushOutbound
    \/ BeginShutdown
    \/ DeliverCallback
    \/ ApplyBackpressure
    \/ FinishClose

TypeOK ==
    /\ state \in States
    /\ commandQ \in Seq({"command"})
    /\ writeQ \in Seq({"write"})
    /\ eventQ \in Seq({"event", "terminal"})
    /\ shutdownRequested \in BOOLEAN
    /\ terminalQueued \in BOOLEAN
    /\ terminalDelivered \in BOOLEAN
    /\ backpressureCount \in Nat

QueueBounds ==
    /\ Len(commandQ) <= MaxCommands
    /\ Len(writeQ) <= MaxWrites
    /\ Len(eventQ) <= MaxEvents

LifecycleMonotonic ==
    state = "Closed" => state' = "Closed"

ClosedIsTerminal ==
    state = "Closed" => UNCHANGED vars

TerminalDeliveredAtMostOnce ==
    terminalDelivered => terminalQueued

BackpressurePreservesAcceptedWork ==
    backpressureCount' > backpressureCount =>
        /\ commandQ' = commandQ
        /\ writeQ' = writeQ
        /\ eventQ' = eventQ

Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(CompleteHandshake \/ BeginShutdown \/ FinishClose)
    /\ WF_vars(FlushOutbound)
    /\ WF_vars(DeliverCallback)

TerminationUnderFairness ==
    shutdownRequested => <>(state = "Closed")

=====================================================================================
