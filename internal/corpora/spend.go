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
	return applyCustodianOperation(ledgerPath, ledger, operation)
}

// UseCustodianGeneration revalidates a previously derived corpus generation
// against the complete active custodian state, then performs the spend and
// protected use while holding the same exclusive lock. Rotation cannot occur
// between revalidation, budget mutation, and the caller's emission/evaluation.
func UseCustodianGeneration(root, protectedRoot string, expected *GeneratedCorpora,
	operation func(*Ledger) error) error {
	if expected == nil || operation == nil {
		return fmt.Errorf("custodian generation and operation are required")
	}
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
	if err := verifyStoredEpochState(root, protectedRoot, ledger.Epoch()); err != nil {
		return fmt.Errorf("STALE_CORPUS_GENERATION: %w", err)
	}
	input, err := LoadGenerationInput(root, protectedRoot)
	if err != nil {
		return fmt.Errorf("STALE_CORPUS_GENERATION: generation input: %w", err)
	}
	current, err := GenerateAll(input)
	if err != nil {
		return fmt.Errorf("STALE_CORPUS_GENERATION: regenerate active corpus: %w", err)
	}
	expectedDigest, err := expected.CanonicalDigest()
	if err != nil {
		return fmt.Errorf("expected corpus identity: %w", err)
	}
	currentDigest, err := current.CanonicalDigest()
	if err != nil {
		return fmt.Errorf("active corpus identity: %w", err)
	}
	if expected.Epoch != ledger.Epoch() || current.Epoch != ledger.Epoch() ||
		expected.PublicSeed != current.PublicSeed || expectedDigest != currentDigest {
		return fmt.Errorf("STALE_CORPUS_GENERATION: expected epoch %d digest %s; active epoch %d digest %s",
			expected.Epoch, expectedDigest, ledger.Epoch(), currentDigest)
	}
	return applyCustodianOperation(ledgerPath, ledger, operation)
}

func applyCustodianOperation(ledgerPath string, ledger *Ledger,
	operation func(*Ledger) error) error {
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
