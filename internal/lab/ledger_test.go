package lab

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

func observedDisagreement() ObservedDisagreement {
	return ObservedDisagreement{
		SubjectRef:            "semantic:server-mask:provisional-v1",
		RFCRefs:               []string{"rfc6455#section-5.1", "rfc6455#section-5.2"},
		RFCExpectationDigest:  intake.DigestBytes([]byte("RFC MUST reject masked server frame")),
		RFCValueDigest:        intake.DigestBytes([]byte("reject")),
		JavaRef:               "java-v1.6.0:scenario-server-mask",
		JavaObservationDigest: intake.DigestBytes([]byte(`{"normalized":"accept"}`)),
		JavaValueDigest:       intake.DigestBytes([]byte("accept")),
		AutobahnRefs:          []string{"autobahn-v25.10.1:1.1"},
		AutobahnResultDigest:  intake.DigestBytes([]byte(`{"case":"1.1","status":"FAIL"}`)),
		AutobahnValueDigest:   intake.DigestBytes([]byte("reject")),
	}
}

func validDelta(t *testing.T) BehaviorDelta {
	t.Helper()
	disagreement := observedDisagreement()
	digest, err := disagreement.Digest()
	if err != nil {
		t.Fatal(err)
	}
	id, err := BehaviorDeltaID(digest)
	if err != nil {
		t.Fatal(err)
	}
	return BehaviorDelta{
		SchemaVersion: "1.0.0", DeltaID: id, SubjectRef: disagreement.SubjectRef,
		RFCRefs: disagreement.RFCRefs, RFCExpectationDigest: disagreement.RFCExpectationDigest, RFCValueDigest: disagreement.RFCValueDigest,
		JavaRef: disagreement.JavaRef, JavaObservationDigest: disagreement.JavaObservationDigest, JavaValueDigest: disagreement.JavaValueDigest,
		AutobahnRefs: disagreement.AutobahnRefs, AutobahnResultDigest: disagreement.AutobahnResultDigest, AutobahnValueDigest: disagreement.AutobahnValueDigest,
		DisagreementDigest: digest, NormativeAuthority: "rfc6455", Disposition: "rfc-governs", Rationale: "RFC 6455 remains normative.",
	}
}

func TestBehaviorLedgerCASAppendIsAtomicUnderConcurrency(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "ledger")
	delta := validDelta(t)
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
	second := validDelta(t)
	second.SubjectRef = "semantic:close-code:provisional-v1"
	second.DisagreementDigest, err = (ObservedDisagreement{
		SubjectRef: second.SubjectRef, RFCRefs: second.RFCRefs, RFCExpectationDigest: second.RFCExpectationDigest, RFCValueDigest: second.RFCValueDigest,
		JavaRef: second.JavaRef, JavaObservationDigest: second.JavaObservationDigest, JavaValueDigest: second.JavaValueDigest,
		AutobahnRefs: second.AutobahnRefs, AutobahnResultDigest: second.AutobahnResultDigest, AutobahnValueDigest: second.AutobahnValueDigest,
	}).Digest()
	if err != nil {
		t.Fatal(err)
	}
	second.DeltaID, err = BehaviorDeltaID(second.DisagreementDigest)
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
	delta := validDelta(t)
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
	delta := validDelta(t)
	delta.NormativeAuthority = "java-v1.6.0"
	assertFinding(t, delta.Validate(), "INVALID_ORACLE_AUTHORITY")
	delta = validDelta(t)
	delta.RFCRefs = []string{"https://attacker.invalid"}
	if err := delta.Validate(); err == nil {
		t.Fatal("unstable RFC reference accepted")
	}
	delta = validDelta(t)
	delta.JavaRef = "java-v1.6.0:different"
	assertFinding(t, delta.Validate(), "BEHAVIOR_DELTA_BINDING_MISMATCH")
}

func TestBehaviorDeltaBindsEveryOracleObservationAndDifferingValue(t *testing.T) {
	for name, mutate := range map[string]func(*BehaviorDelta){
		"rfc expectation": func(delta *BehaviorDelta) { delta.RFCExpectationDigest = intake.DigestBytes([]byte("mutated RFC")) },
		"rfc value":       func(delta *BehaviorDelta) { delta.RFCValueDigest = intake.DigestBytes([]byte("mutated RFC value")) },
		"java observation": func(delta *BehaviorDelta) {
			delta.JavaObservationDigest = intake.DigestBytes([]byte("mutated Java observation"))
		},
		"java value": func(delta *BehaviorDelta) { delta.JavaValueDigest = intake.DigestBytes([]byte("mutated Java value")) },
		"autobahn result": func(delta *BehaviorDelta) {
			delta.AutobahnResultDigest = intake.DigestBytes([]byte("mutated Autobahn result"))
		},
		"autobahn value": func(delta *BehaviorDelta) {
			delta.AutobahnValueDigest = intake.DigestBytes([]byte("mutated Autobahn value"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			delta := validDelta(t)
			mutate(&delta)
			assertFinding(t, delta.Validate(), "BEHAVIOR_DELTA_BINDING_MISMATCH")
		})
	}
	disagreement := observedDisagreement()
	disagreement.JavaValueDigest = disagreement.RFCValueDigest
	disagreement.AutobahnValueDigest = disagreement.RFCValueDigest
	assertFinding(t, func() error { _, err := disagreement.Digest(); return err }(), "NO_BEHAVIOR_DISAGREEMENT")
	delta := validDelta(t)
	delta.JavaObservationDigest = intake.DigestBytes([]byte("new exact observation"))
	updated := observedDisagreement()
	updated.JavaObservationDigest = delta.JavaObservationDigest
	digest, err := updated.Digest()
	if err != nil {
		t.Fatal(err)
	}
	delta.DisagreementDigest = digest
	assertFinding(t, delta.Validate(), "BEHAVIOR_DELTA_IDENTITY_MISMATCH")
}
