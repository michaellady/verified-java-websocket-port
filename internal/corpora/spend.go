package corpora

import (
	"fmt"
	"os"
)

// SpendCustodian atomically applies one ledger operation: an exclusive file
// lock serializes concurrent invocations around the load-spend-persist cycle,
// and the ledger is persisted even when the operation is denied, so denial
// entries and the probing latch always land on disk.
func SpendCustodian(protectedRoot string, operation func(*Ledger) error) error {
	ledgerPath := ProtectedLedgerPath(protectedRoot)
	unlock, err := acquireFileLock(ledgerPath + ".lock")
	if err != nil {
		return fmt.Errorf("custodian ledger lock: %w", err)
	}
	defer unlock()

	raw, err := os.ReadFile(ledgerPath)
	if err != nil {
		return fmt.Errorf("custodian ledger unavailable: %w", err)
	}
	ledger, err := LoadLedger(raw)
	if err != nil {
		return fmt.Errorf("custodian ledger invalid: %w", err)
	}
	operationErr := operation(ledger)
	serialized, err := ledger.Serialize()
	if err != nil {
		return err
	}
	if err := os.WriteFile(ledgerPath, serialized, 0o644); err != nil {
		return err
	}
	return operationErr
}
