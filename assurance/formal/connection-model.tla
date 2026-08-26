------------------------------ MODULE ConnectionModel ------------------------------
EXTENDS Naturals, Sequences, FiniteSets

States == {"Connecting", "Open", "Closing", "Closed"}
MaxCommands == 2
MaxWrites == 2
MaxEvents == 2

VARIABLES state, commandQ, writeQ, eventQ, shutdownRequested,
          terminalQueued, terminalDelivered, backpressureCount,
          acceptedCount, disposedCount, terminalDeliveryCount

vars == <<state, commandQ, writeQ, eventQ, shutdownRequested,
          terminalQueued, terminalDelivered, backpressureCount,
          acceptedCount, disposedCount, terminalDeliveryCount>>

Init ==
    /\ state = "Connecting"
    /\ commandQ = <<>>
    /\ writeQ = <<>>
    /\ eventQ = <<>>
    /\ shutdownRequested = FALSE
    /\ terminalQueued = FALSE
    /\ terminalDelivered = FALSE
    /\ backpressureCount = 0
    /\ acceptedCount = 0
    /\ disposedCount = 0
    /\ terminalDeliveryCount = 0

CompleteHandshake ==
    /\ state = "Connecting"
    /\ state' = "Open"
    /\ UNCHANGED <<commandQ, writeQ, eventQ, shutdownRequested,
                   terminalQueued, terminalDelivered, backpressureCount,
                   acceptedCount, disposedCount, terminalDeliveryCount>>

EnqueueCommand ==
    /\ state \in {"Open", "Closing"}
    /\ Len(commandQ) < MaxCommands
    /\ commandQ' = Append(commandQ, "command")
    /\ acceptedCount' = acceptedCount + 1
    /\ UNCHANGED <<state, writeQ, eventQ, shutdownRequested,
                   terminalQueued, terminalDelivered, backpressureCount,
                   disposedCount, terminalDeliveryCount>>

ReceiveFrame ==
    /\ state = "Open"
    /\ Len(eventQ) < MaxEvents
    /\ eventQ' = Append(eventQ, "event")
    /\ UNCHANGED <<state, commandQ, writeQ, shutdownRequested,
                   terminalQueued, terminalDelivered, backpressureCount,
                   acceptedCount, disposedCount, terminalDeliveryCount>>

ReceiveClose ==
    /\ state \in {"Open", "Closing"}
    /\ Len(eventQ) < MaxEvents
    /\ state' = "Closing"
    /\ eventQ' = Append(eventQ, "terminal")
    /\ terminalQueued' = TRUE
    /\ UNCHANGED <<commandQ, writeQ, shutdownRequested,
                   terminalDelivered, backpressureCount, acceptedCount,
                   disposedCount, terminalDeliveryCount>>

FlushOutbound ==
    \/ /\ Len(commandQ) > 0
       /\ Len(writeQ) < MaxWrites
       /\ commandQ' = Tail(commandQ)
       /\ writeQ' = Append(writeQ, "write")
       /\ disposedCount' = disposedCount + 1
       /\ UNCHANGED <<state, eventQ, shutdownRequested, terminalQueued,
                      terminalDelivered, backpressureCount, acceptedCount,
                      terminalDeliveryCount>>
    \/ /\ Len(writeQ) > 0
       /\ writeQ' = Tail(writeQ)
       /\ UNCHANGED <<state, commandQ, eventQ, shutdownRequested,
                      terminalQueued, terminalDelivered, backpressureCount,
                      acceptedCount, disposedCount, terminalDeliveryCount>>

BeginShutdown ==
    /\ shutdownRequested = FALSE
    /\ state \in {"Connecting", "Open", "Closing"}
    /\ shutdownRequested' = TRUE
    /\ state' = "Closing"
    /\ UNCHANGED <<commandQ, writeQ, eventQ, terminalQueued,
                   terminalDelivered, backpressureCount, acceptedCount,
                   disposedCount, terminalDeliveryCount>>

DeliverCallback ==
    /\ Len(eventQ) > 0
    /\ Head(eventQ) # "terminal" \/ terminalDeliveryCount = 0
    /\ eventQ' = Tail(eventQ)
    /\ terminalDelivered' = terminalDelivered \/ (Head(eventQ) = "terminal")
    /\ terminalDeliveryCount' =
           IF Head(eventQ) = "terminal" THEN terminalDeliveryCount + 1
           ELSE terminalDeliveryCount
    /\ UNCHANGED <<state, commandQ, writeQ, shutdownRequested,
                   terminalQueued, backpressureCount, acceptedCount, disposedCount>>

ApplyBackpressure ==
    /\ Len(commandQ) = MaxCommands \/ Len(writeQ) = MaxWrites \/ Len(eventQ) = MaxEvents
    /\ backpressureCount' = backpressureCount + 1
    /\ UNCHANGED <<state, commandQ, writeQ, eventQ, shutdownRequested,
                   terminalQueued, terminalDelivered, acceptedCount,
                   disposedCount, terminalDeliveryCount>>

FinishClose ==
    /\ state = "Closing"
    /\ Len(commandQ) = 0
    /\ Len(writeQ) = 0
    /\ disposedCount = acceptedCount
    /\ (~terminalQueued \/ terminalDelivered)
    /\ state' = "Closed"
    /\ UNCHANGED <<commandQ, writeQ, eventQ, shutdownRequested,
                   terminalQueued, terminalDelivered, backpressureCount,
                   acceptedCount, disposedCount, terminalDeliveryCount>>

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
    /\ acceptedCount \in Nat
    /\ disposedCount \in Nat
    /\ terminalDeliveryCount \in Nat

QueueBounds ==
    /\ Len(commandQ) <= MaxCommands
    /\ Len(writeQ) <= MaxWrites
    /\ Len(eventQ) <= MaxEvents

LifecycleMonotonic ==
    state = "Closed" => state' = "Closed"

ClosedIsTerminal ==
    state = "Closed" => UNCHANGED vars

TerminalDeliveredAtMostOnce ==
    /\ terminalDeliveryCount <= 1
    /\ terminalDelivered = (terminalDeliveryCount = 1)

AcceptedCommandsDisposedExactlyOnce ==
    disposedCount <= acceptedCount

AcceptedCommandsEventuallyDisposed ==
    []((acceptedCount > disposedCount) => <>(disposedCount = acceptedCount))

TerminalDeliveryEventually ==
    []((terminalQueued /\ ~terminalDelivered) => <>terminalDelivered)

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
