package securitygate

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

// TestB1CoordinatedBundleMutationFailsClosed constructs exactly the coordinated
// mutation the review named: mutate a retained descriptor observation, recompute
// and re-pin the self-referential evidence digest, keep the known projection
// digest string. It must still fail closed because the retained proof is pinned
// to its exact bytes (sbxLiveEvidenceDigest), not merely self-consistent.
func TestB1CoordinatedBundleMutationFailsClosed(t *testing.T) {
	snapshot, err := loadPolicies(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.root.Close()
	if findings := verifyRetainedEvidence(snapshot); len(findings) != 0 {
		t.Fatalf("baseline retained evidence not clean: %#v", findings)
	}
	var doc sbxLiveEvidenceDocument
	if err := intake.DecodeStrict(snapshot.bytes[sbxLiveEvidencePath], &doc); err != nil {
		t.Fatal(err)
	}
	for i := range doc.Descriptors {
		if doc.Descriptors[i].ID == "CACHE_WRITE_DENIED" {
			// still a plausible EXITED wall duration, so the internal outcome
			// validator would accept it — only the exact-byte pin catches it.
			doc.Descriptors[i].WallDurationNanos += 1000
		}
	}
	mutated, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.bytes[sbxLiveEvidencePath] = mutated
	newDigest := intake.DigestBytes(mutated)
	// Attacker keeps the bundle self-consistent: the loaded digest and the
	// evidence binding's self-referential digest both point at the mutated bytes,
	// and the projection digest string is left at its known-good value.
	snapshot.digests[sbxLiveEvidencePath] = newDigest
	e := snapshot.evidence
	e.SbxLiveEvidence.EvidenceDigest = newDigest
	snapshot.evidence = e
	findings := verifyRetainedEvidence(snapshot)
	if len(findings) != 1 || findings[0].Code != "SANDBOX_ENFORCEMENT_UNAVAILABLE" || findings[0].Disposition != "BLOCK" {
		t.Fatalf("coordinated bundle mutation was not rejected: %#v", findings)
	}
}

// TestB1ExactDescriptorComparisonFailsClosed exercises the independent descriptor
// cross-check: even an observation change that the internal outcome validator
// would accept (a larger CPU peak) is caught because it no longer equals the
// byte-pinned protected projection observation.
func TestB1ExactDescriptorComparisonFailsClosed(t *testing.T) {
	snapshot, err := loadPolicies(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.root.Close()
	if finding := compareRetainedDescriptorOutcomes(snapshot); finding != nil {
		t.Fatalf("baseline descriptor comparison not clean: %#v", finding)
	}
	var doc sbxLiveEvidenceDocument
	if err := intake.DecodeStrict(snapshot.bytes[sbxLiveEvidencePath], &doc); err != nil {
		t.Fatal(err)
	}
	for i := range doc.Descriptors {
		if doc.Descriptors[i].ID == "CPU_BOUND" {
			doc.Descriptors[i].CPUUsageUsecPeak += 1
		}
	}
	mutated, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.bytes[sbxLiveEvidencePath] = mutated
	finding := compareRetainedDescriptorOutcomes(snapshot)
	if finding == nil || finding.Code != "SANDBOX_ENFORCEMENT_UNAVAILABLE" || finding.Disposition != "BLOCK" {
		t.Fatalf("mutated observation not caught against the retained projection: %#v", finding)
	}
}

// TestB2PolicyEnvelopeWideningFailsClosed widens one sandbox-policy resource and
// the required-capability set (the post-regenerate state) and asserts the gate
// binds them to attempt 0123's exact proven envelope.
func TestB2PolicyEnvelopeWideningFailsClosed(t *testing.T) {
	snapshot, err := loadPolicies(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.root.Close()
	if findings := verifyRetainedEvidence(snapshot); len(findings) != 0 {
		t.Fatalf("baseline retained evidence not clean: %#v", findings)
	}
	originalResources := snapshot.sandbox.Resources
	snapshot.sandbox.Resources.MemoryBytes = originalResources.MemoryBytes * 2
	findings := verifyRetainedEvidence(snapshot)
	if len(findings) != 1 || findings[0].Code != "SANDBOX_CAPABILITY_MISMATCH" {
		t.Fatalf("widened memory limit not rejected: %#v", findings)
	}
	snapshot.sandbox.Resources = originalResources

	originalCaps := snapshot.sandbox.RequiredCapabilities
	snapshot.sandbox.RequiredCapabilities = append(append([]string{}, originalCaps...), "CAP_SYS_ADMIN")
	findings = verifyRetainedEvidence(snapshot)
	if len(findings) != 1 || findings[0].Code != "SANDBOX_CAPABILITY_MISMATCH" {
		t.Fatalf("widened capability set not rejected: %#v", findings)
	}
	snapshot.sandbox.RequiredCapabilities = originalCaps
}

// TestB3ASProfileBothDirectionsFailClosed proves the per-descriptor RLIMIT_AS
// profile is bound memory-only-tight in BOTH directions: the memory canary must
// carry the tight 512 MiB cap, and no other descriptor may.
func TestB3ASProfileBothDirectionsFailClosed(t *testing.T) {
	exit0, exit2 := 0, 2
	memoryLoose := sbxLiveDescriptorOutcome{ID: "MEMORY_BOUND", Expected: "RLIMIT_AS_ALLOCATION_FAILURE_EXIT_2", Termination: "PARENT_OBSERVED_NONZERO_EXIT", ExitCode: &exit2, RLimitASBytes: ^uint64(0)}
	if finding := validateSbxLiveDescriptorOutcome(memoryLoose); finding == nil || finding.Code != "SANDBOX_ENFORCEMENT_UNAVAILABLE" {
		t.Fatalf("memory canary with loose AS accepted: %#v", finding)
	}
	shellTight := sbxLiveDescriptorOutcome{ID: "CACHE_WRITE_DENIED", Expected: "EXIT_0_DENIED", Termination: "EXITED", ExitCode: &exit0, RLimitASBytes: sbxLiveMemoryRLimitASBytes}
	if finding := validateSbxLiveDescriptorOutcome(shellTight); finding == nil || finding.Code != "SANDBOX_ENFORCEMENT_UNAVAILABLE" {
		t.Fatalf("non-memory descriptor with tight AS accepted: %#v", finding)
	}
	// Positive control: the shipped memory-only-tight profile is accepted.
	memoryTight := sbxLiveDescriptorOutcome{ID: "MEMORY_BOUND", Expected: "RLIMIT_AS_ALLOCATION_FAILURE_EXIT_2", Termination: "PARENT_OBSERVED_NONZERO_EXIT", ExitCode: &exit2, RLimitASBytes: sbxLiveMemoryRLimitASBytes}
	if finding := validateSbxLiveDescriptorOutcome(memoryTight); finding != nil {
		t.Fatalf("valid memory canary rejected: %#v", finding)
	}
	shellLoose := sbxLiveDescriptorOutcome{ID: "CACHE_WRITE_DENIED", Expected: "EXIT_0_DENIED", Termination: "EXITED", ExitCode: &exit0, RLimitASBytes: ^uint64(0)}
	if finding := validateSbxLiveDescriptorOutcome(shellLoose); finding != nil {
		t.Fatalf("valid loose-AS shell descriptor rejected: %#v", finding)
	}
}

// TestI1AcceptDispositionStructurallySafe proves the ACCEPT disposition is
// structurally reserved for exactly one code: a second ACCEPT row, and an ACCEPT
// on any other (hostile) code, both fail closed at policy load — not by comment.
func TestI1AcceptDispositionStructurallySafe(t *testing.T) {
	permitted := []byte(`{"code":"SANDBOX_RLIMIT_ENVELOPE_PROVEN_LIVE","disposition":"ACCEPT"}`)

	t.Run("second-accept-row", func(t *testing.T) {
		root := copySecurityInputs(t)
		policyPath := filepath.Join(root, "security", "sandbox-policy.json")
		data, err := os.ReadFile(policyPath)
		if err != nil {
			t.Fatal(err)
		}
		injected := bytes.Replace(data, permitted, append(append([]byte{}, permitted...), []byte(`,{"code":"HOSTILE_ACCEPT","disposition":"ACCEPT"}`)...), 1)
		if bytes.Equal(injected, data) {
			t.Fatal("failed to inject second ACCEPT row")
		}
		if err := os.WriteFile(policyPath, injected, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadPolicies(root); err == nil || !strings.Contains(err.Error(), "ACCEPT disposition is reserved") {
			t.Fatalf("second ACCEPT row not rejected: %v", err)
		}
	})

	t.Run("hostile-code-accept", func(t *testing.T) {
		root := copySecurityInputs(t)
		policyPath := filepath.Join(root, "security", "sandbox-policy.json")
		data, err := os.ReadFile(policyPath)
		if err != nil {
			t.Fatal(err)
		}
		mutated := bytes.Replace(data,
			[]byte(`{"code":"AUTOBAHN_RERUN_FORBIDDEN","disposition":"BLOCK"}`),
			[]byte(`{"code":"AUTOBAHN_RERUN_FORBIDDEN","disposition":"ACCEPT"}`), 1)
		if bytes.Equal(mutated, data) {
			t.Fatal("failed to flip a hostile code to ACCEPT")
		}
		if err := os.WriteFile(policyPath, mutated, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadPolicies(root); err == nil || !strings.Contains(err.Error(), "ACCEPT disposition is reserved") {
			t.Fatalf("ACCEPT on a hostile code not rejected: %v", err)
		}
	})
}
