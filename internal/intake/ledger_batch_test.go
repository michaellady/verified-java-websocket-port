package intake

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestFileLedgerCommitsNonceBatchAsOneAtomicManifest(t *testing.T) {
	ledger := FileLedger{Directory: filepath.Join(t.TempDir(), "ledger")}
	claims := []NonceClaim{
		{ActorID: RequiredOwnerActor, Nonce: "nonce-ledger-batch-000000001"},
		{ActorID: RequiredOwnerActor, Nonce: "nonce-ledger-batch-000000002"},
		{ActorID: RequiredOwnerActor, Nonce: "nonce-ledger-batch-000000003"},
		{ActorID: RequiredOwnerActor, Nonce: "nonce-ledger-batch-000000004"},
	}
	if !ledger.ConsumeBatch(claims) {
		t.Fatal("valid nonce batch was denied")
	}
	entries, err := os.ReadDir(ledger.Directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), ".batch") {
		t.Fatalf("ledger committed non-atomic state: %+v", entries)
	}
}

func TestFileLedgerIgnoresAndRemovesUncommittedCrashTemp(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "ledger")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	partial := filepath.Join(directory, ".nonce-batch-crashed.tmp")
	if err := os.WriteFile(partial, []byte(`{"schema_version":"1.0.0","claims":[`), 0o600); err != nil {
		t.Fatal(err)
	}
	ledger := FileLedger{Directory: directory}
	if !ledger.Consume(RequiredOwnerActor, "nonce-after-crash-temp-000001") {
		t.Fatal("uncommitted crash temp blocked a fresh batch")
	}
	if _, err := os.Lstat(partial); !os.IsNotExist(err) {
		t.Fatalf("uncommitted crash temp remains: %v", err)
	}
}

func TestFileLedgerRejectsIndividualReplayAcrossBatches(t *testing.T) {
	ledger := FileLedger{Directory: filepath.Join(t.TempDir(), "ledger")}
	first := []NonceClaim{
		{ActorID: RequiredOwnerActor, Nonce: "nonce-shared-across-batches-001"},
		{ActorID: RequiredOwnerActor, Nonce: "nonce-first-batch-only-000001"},
	}
	second := []NonceClaim{
		{ActorID: RequiredOwnerActor, Nonce: "nonce-shared-across-batches-001"},
		{ActorID: RequiredOwnerActor, Nonce: "nonce-second-batch-only-00001"},
	}
	if !ledger.ConsumeBatch(first) {
		t.Fatal("first batch denied")
	}
	if ledger.ConsumeBatch(second) {
		t.Fatal("individual nonce replay across committed batches was accepted")
	}
	entries, err := os.ReadDir(ledger.Directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("denied replay changed ledger: %d entries", len(entries))
	}
}

func TestFileLedgerFailsClosedOnMalformedOrUnsafeCommittedState(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		setup func(*testing.T, string)
	}{
		{
			name: "malformed-manifest",
			setup: func(t *testing.T, directory string) {
				t.Helper()
				data := []byte(`{"schema_version":"1.0.0","claims":["not-a-digest"]}`)
				name := DigestBytes(data)[7:] + ".batch"
				if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unsafe-symlink",
			setup: func(t *testing.T, directory string) {
				t.Helper()
				target := filepath.Join(t.TempDir(), "target")
				if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, filepath.Join(directory, strings.Repeat("a", 64)+".batch")); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "ledger")
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			testCase.setup(t, directory)
			ledger := FileLedger{Directory: directory}
			if ledger.Consume(RequiredOwnerActor, "nonce-malformed-state-000001") {
				t.Fatal("unsafe committed ledger state was accepted")
			}
		})
	}
}

func TestFileLedgerSerializesConcurrentOverlappingBatches(t *testing.T) {
	ledger := FileLedger{Directory: filepath.Join(t.TempDir(), "ledger")}
	const callers = 24
	results := make(chan bool, callers)
	start := make(chan struct{})
	var group sync.WaitGroup
	for index := range callers {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			results <- ledger.ConsumeBatch([]NonceClaim{
				{ActorID: RequiredOwnerActor, Nonce: "nonce-concurrent-shared-000001"},
				{ActorID: RequiredOwnerActor, Nonce: fmt.Sprintf("nonce-concurrent-unique-%06d", index)},
			})
		}()
	}
	close(start)
	group.Wait()
	close(results)
	winners := 0
	for result := range results {
		if result {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("got %d committed overlapping batches, want 1", winners)
	}
	entries, err := os.ReadDir(ledger.Directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), ".batch") {
		t.Fatalf("concurrent ledger left non-atomic state: %+v", entries)
	}
}

func TestFileLedgerFailsClosedOnStaleCrashLock(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "ledger")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, ".nonce-batch.lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ledger := FileLedger{Directory: directory}
	if ledger.Consume(RequiredOwnerActor, "nonce-stale-crash-lock-00001") {
		t.Fatal("stale crash lock was bypassed")
	}
}
