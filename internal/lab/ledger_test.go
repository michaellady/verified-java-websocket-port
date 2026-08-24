package lab

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

func observedDisagreement() ObservedDisagreement {
	return ObservedDisagreement{
		SubjectRef:   "semantic:server-mask:provisional-v1",
		RFCRefs:      []string{"rfc6455#section-5.1", "rfc6455#section-5.2"},
		JavaRef:      "java-v1.6.0:scenario-server-mask",
		AutobahnRefs: []string{"autobahn-v25.10.1:1.1"},
	}
}

func validDelta(t *testing.T, id string) BehaviorDelta {
	t.Helper()
	disagreement := observedDisagreement()
	digest, err := disagreement.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return BehaviorDelta{
		SchemaVersion: "1.0.0", DeltaID: id, SubjectRef: disagreement.SubjectRef,
		RFCRefs: disagreement.RFCRefs, JavaRef: disagreement.JavaRef, AutobahnRefs: disagreement.AutobahnRefs,
		DisagreementDigest: digest, NormativeAuthority: "rfc6455", Disposition: "rfc-governs", Rationale: "RFC 6455 remains normative.",
	}
}

func TestBehaviorLedgerCASAppendIsAtomicUnderConcurrency(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "ledger")
	delta := validDelta(t, "delta-000000000000001")
	const writers = 24
	var successes atomic.Int32
	var wait sync.WaitGroup
	wait.Add(writers)
	for index := 0; index < writers; index++ {
		go func() {
			defer wait.Done()
			if _, err := AppendBehaviorDelta(directory, GenesisLedgerHead, delta); err == nil {
				successes.Add(1)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful concurrent appends = %d", successes.Load())
	}
	records, head, err := ReadBehaviorLedger(directory)
	if err != nil || len(records) != 1 || head == GenesisLedgerHead {
		t.Fatalf("records=%d head=%s err=%v", len(records), head, err)
	}
	second := validDelta(t, "delta-000000000000002")
	second.SubjectRef = "semantic:close-code:provisional-v1"
	second.DisagreementDigest, err = (ObservedDisagreement{SubjectRef: second.SubjectRef, RFCRefs: second.RFCRefs, JavaRef: second.JavaRef, AutobahnRefs: second.AutobahnRefs}).Digest()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AppendBehaviorDelta(directory, GenesisLedgerHead, second); err == nil {
		t.Fatal("stale CAS head accepted")
	}
	if _, err := AppendBehaviorDelta(directory, head, second); err != nil {
		t.Fatal(err)
	}
	records, _, err = ReadBehaviorLedger(directory)
	if err != nil || len(records) != 2 {
		t.Fatalf("records=%d err=%v", len(records), err)
	}
}

func TestBehaviorLedgerDetectsUnledgeredAndCorruptRecords(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "ledger")
	delta := validDelta(t, "delta-000000000000001")
	if _, err := AppendBehaviorDelta(directory, GenesisLedgerHead, delta); err != nil {
		t.Fatal(err)
	}
	records, _, err := ReadBehaviorLedger(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := DetectUnledgeredDisagreements(records, []ObservedDisagreement{observedDisagreement()}); err != nil {
		t.Fatal(err)
	}
	unledgered := observedDisagreement()
	unledgered.JavaRef = "java-v1.6.0:other-scenario"
	assertFinding(t, DetectUnledgeredDisagreements(records, []ObservedDisagreement{unledgered}), "UNLEDGERED_BEHAVIOR_DISAGREEMENT")

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var recordPath string
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".delta" {
			recordPath = filepath.Join(directory, entry.Name())
		}
	}
	bytes, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(recordPath); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(t.TempDir(), "external")
	if err := os.WriteFile(external, bytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(external, recordPath); err != nil {
		t.Fatal(err)
	}
	_, _, err = ReadBehaviorLedger(directory)
	assertFinding(t, err, "UNSAFE_FILE")
}

func TestBehaviorDeltaNeverElevatesJavaOverRFC(t *testing.T) {
	delta := validDelta(t, "delta-000000000000001")
	delta.NormativeAuthority = "java-v1.6.0"
	assertFinding(t, delta.Validate(), "INVALID_ORACLE_AUTHORITY")
	delta = validDelta(t, "delta-000000000000001")
	delta.RFCRefs = []string{"https://attacker.invalid"}
	if err := delta.Validate(); err == nil {
		t.Fatal("unstable RFC reference accepted")
	}
	var findingValue *intake.Finding
	if !errors.As(SandboxEnforcementUnavailable("x"), &findingValue) {
		t.Fatal("lab errors must preserve intake.Finding API")
	}
	delta = validDelta(t, "delta-000000000000001")
	delta.JavaRef = "java-v1.6.0:different"
	assertFinding(t, delta.Validate(), "BEHAVIOR_DELTA_BINDING_MISMATCH")
}
