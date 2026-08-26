package corpora

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// CustodianPolicy governs held-out access: monotonic budgets, probing
// detection, rotation, and canary counts. The custodian and classifier run
// outside any candidate sandbox; this policy is enforced by the Ledger.
type CustodianPolicy struct {
	QueryBudget      int `json:"query_budget"`
	DiagnosticBudget int `json:"diagnostic_budget"`
	RepeatThreshold  int `json:"repeat_threshold"`
	CanariesPerTier  int `json:"canaries_per_tier"`
}

// DefaultCustodianPolicy is the committed US-005 custodian policy.
func DefaultCustodianPolicy() CustodianPolicy {
	return CustodianPolicy{
		QueryBudget:      200,
		DiagnosticBudget: 50,
		RepeatThreshold:  3,
		CanariesPerTier:  canariesPerTier,
	}
}

// CustodianPolicyDocument renders the canonical protected policy document.
func CustodianPolicyDocument(policy CustodianPolicy, epoch int) ([]byte, error) {
	return CanonicalJSON(map[string]any{
		"schema_version":    "1.0.0",
		"policy_id":         "us005-custodian-policy",
		"epoch":             epoch,
		"query_budget":      policy.QueryBudget,
		"diagnostic_budget": policy.DiagnosticBudget,
		"budgets":           "monotonic non-increasing within an epoch; enforced by the hash-chained ledger",
		"rotation": map[string]any{
			"mechanism": "epoch increment re-derives hidden and sealed tiers, salts, and canaries from the protected master secret",
			"trigger":   "budget exhaustion, probing detection, or owner decision",
		},
		"probing": map[string]any{
			"repeat_threshold": policy.RepeatThreshold,
			"detection": "byte-identical query digests repeated against held-out tiers; " +
				"detection is exact-digest equality, no similarity claim",
			"action": "latch probing flag, deny all further queries, require rotation",
		},
		"canaries": map[string]any{
			"per_tier":   policy.CanariesPerTier,
			"mechanics":  "secret-derived tokens embedded in held-out scenarios; any public artifact containing a token is a leak finding",
			"disclosure": "canary ids and tokens never leave the protected store",
		},
		"boundary":                   "custodian and classifier run outside the candidate sandbox; candidate execution uses the accepted US-007 sbx workload profile with no network, shared skills, local MCP, secrets, or protected-store mounts",
		"assurance":                  "OWNER_ATTESTED_NOT_INDEPENDENT",
		"independent_review_claimed": false,
		"production":                 false,
		"signing":                    false,
		"publication":                false,
	})
}

// LedgerEntry is one hash-chained custodian ledger record. Denial entries
// (query_denied, diagnostic_denied) additionally record the reason, actor,
// and time so post-lockout probing stays auditable.
type LedgerEntry struct {
	Seq                 int    `json:"seq"`
	PrevDigest          string `json:"prev_digest"`
	Op                  string `json:"op"`
	Epoch               int    `json:"epoch"`
	ScenarioRef         string `json:"scenario_ref,omitempty"`
	QueryDigest         string `json:"query_digest,omitempty"`
	QueryRemaining      int    `json:"query_remaining"`
	DiagnosticRemaining int    `json:"diagnostic_remaining"`
	ProbingDetected     bool   `json:"probing_detected"`
	Reason              string `json:"reason,omitempty"`
	Actor               string `json:"actor,omitempty"`
	At                  string `json:"at,omitempty"`
}

func (e LedgerEntry) toMap() map[string]any {
	out := map[string]any{
		"seq":                  e.Seq,
		"prev_digest":          e.PrevDigest,
		"op":                   e.Op,
		"epoch":                e.Epoch,
		"query_remaining":      e.QueryRemaining,
		"diagnostic_remaining": e.DiagnosticRemaining,
		"probing_detected":     e.ProbingDetected,
	}
	if e.ScenarioRef != "" {
		out["scenario_ref"] = e.ScenarioRef
	}
	if e.QueryDigest != "" {
		out["query_digest"] = e.QueryDigest
	}
	if e.Reason != "" {
		out["reason"] = e.Reason
	}
	if e.Actor != "" {
		out["actor"] = e.Actor
	}
	if e.At != "" {
		out["at"] = e.At
	}
	return out
}

func (e LedgerEntry) digest() (string, error) {
	line, err := CanonicalJSON(e.toMap())
	if err != nil {
		return "", err
	}
	return DigestSHA256(line), nil
}

// Ledger enforces the custodian policy as an append-only hash chain.
type Ledger struct {
	policy      CustodianPolicy
	entries     []LedgerEntry
	queryCounts map[string]int
	now         func() string
	actor       string
}

// Entries returns a copy of the chain for inspection.
func (l *Ledger) Entries() []LedgerEntry {
	return append([]LedgerEntry{}, l.entries...)
}

func defaultLedgerClock() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func defaultLedgerActor() string {
	if user := os.Getenv("USER"); user != "" {
		return user
	}
	return "owner"
}

// denial appends a hash-chained denial record; budgets and the probing latch
// are carried forward unchanged.
func (l *Ledger) denial(op, scenarioRef, queryDigest, reason string) error {
	last := l.last()
	return l.append(LedgerEntry{
		Op:                  op,
		Epoch:               last.Epoch,
		ScenarioRef:         scenarioRef,
		QueryDigest:         queryDigest,
		QueryRemaining:      last.QueryRemaining,
		DiagnosticRemaining: last.DiagnosticRemaining,
		ProbingDetected:     last.ProbingDetected,
		Reason:              reason,
		Actor:               l.actor,
		At:                  l.now(),
	})
}

// NewLedger opens a fresh ledger with a genesis entry for the epoch.
func NewLedger(policy CustodianPolicy, epoch int) (*Ledger, error) {
	if policy.QueryBudget < 1 || policy.DiagnosticBudget < 1 || policy.RepeatThreshold < 2 {
		return nil, fmt.Errorf("custodian policy budgets and threshold must be positive")
	}
	ledger := &Ledger{policy: policy, queryCounts: map[string]int{},
		now: defaultLedgerClock, actor: defaultLedgerActor()}
	genesis := LedgerEntry{
		Seq:                 0,
		PrevDigest:          "sha256:" + zero64(),
		Op:                  "genesis",
		Epoch:               epoch,
		QueryRemaining:      policy.QueryBudget,
		DiagnosticRemaining: policy.DiagnosticBudget,
	}
	ledger.entries = append(ledger.entries, genesis)
	return ledger, nil
}

func zero64() string {
	return "0000000000000000000000000000000000000000000000000000000000000000"
}

func (l *Ledger) last() LedgerEntry {
	return l.entries[len(l.entries)-1]
}

// Epoch reports the active rotation epoch.
func (l *Ledger) Epoch() int { return l.last().Epoch }

// ProbingDetected reports whether the probing latch is set.
func (l *Ledger) ProbingDetected() bool { return l.last().ProbingDetected }

// Budgets are the remaining budgets.
type Budgets struct {
	Query      int
	Diagnostic int
}

// Remaining reports the remaining budgets.
func (l *Ledger) Remaining() Budgets {
	last := l.last()
	return Budgets{Query: last.QueryRemaining, Diagnostic: last.DiagnosticRemaining}
}

func (l *Ledger) append(entry LedgerEntry) error {
	prev := l.last()
	// Monotonicity is structural: budgets never increase within an epoch.
	if entry.Epoch == prev.Epoch &&
		(entry.QueryRemaining > prev.QueryRemaining ||
			entry.DiagnosticRemaining > prev.DiagnosticRemaining) {
		return fmt.Errorf("BUDGET_MONOTONICITY_VIOLATION")
	}
	prevDigest, err := prev.digest()
	if err != nil {
		return err
	}
	entry.Seq = prev.Seq + 1
	entry.PrevDigest = prevDigest
	l.entries = append(l.entries, entry)
	return nil
}

// RecordQuery spends one query against held-out content. Probing detection
// is exact: the same query digest repeated RepeatThreshold times latches the
// custodian until rotation.
func (l *Ledger) RecordQuery(scenarioRef, queryDigest string) error {
	last := l.last()
	if last.ProbingDetected {
		if err := l.denial("query_denied", scenarioRef, queryDigest, "CUSTODIAN_LOCKED"); err != nil {
			return err
		}
		return fmt.Errorf("CUSTODIAN_LOCKED: probing detected; rotation required")
	}
	if last.QueryRemaining < 1 {
		if err := l.denial("query_denied", scenarioRef, queryDigest, "QUERY_BUDGET_EXHAUSTED"); err != nil {
			return err
		}
		return fmt.Errorf("QUERY_BUDGET_EXHAUSTED")
	}
	l.queryCounts[queryDigest]++
	if l.queryCounts[queryDigest] >= l.policy.RepeatThreshold {
		// The request that trips probing detection is itself denied, so its
		// own ledger entry is a hash-chained denial record — reason, actor,
		// time, latch set — never a success entry, and it spends no budget.
		if err := l.append(LedgerEntry{
			Op:                  "query_denied",
			Epoch:               last.Epoch,
			ScenarioRef:         scenarioRef,
			QueryDigest:         queryDigest,
			QueryRemaining:      last.QueryRemaining,
			DiagnosticRemaining: last.DiagnosticRemaining,
			ProbingDetected:     true,
			Reason:              "PROBING_DETECTED",
			Actor:               l.actor,
			At:                  l.now(),
		}); err != nil {
			return err
		}
		return fmt.Errorf("PROBING_DETECTED: query digest repeated %d times",
			l.queryCounts[queryDigest])
	}
	return l.append(LedgerEntry{
		Op:                  "query",
		Epoch:               last.Epoch,
		ScenarioRef:         scenarioRef,
		QueryDigest:         queryDigest,
		QueryRemaining:      last.QueryRemaining - 1,
		DiagnosticRemaining: last.DiagnosticRemaining,
	})
}

// RecordDiagnostic spends one diagnostic disclosure.
func (l *Ledger) RecordDiagnostic(scenarioRef, queryDigest string) error {
	last := l.last()
	if last.ProbingDetected {
		if err := l.denial("diagnostic_denied", scenarioRef, queryDigest, "CUSTODIAN_LOCKED"); err != nil {
			return err
		}
		return fmt.Errorf("CUSTODIAN_LOCKED: probing detected; rotation required")
	}
	if last.DiagnosticRemaining < 1 {
		if err := l.denial("diagnostic_denied", scenarioRef, queryDigest, "DIAGNOSTIC_BUDGET_EXHAUSTED"); err != nil {
			return err
		}
		return fmt.Errorf("DIAGNOSTIC_BUDGET_EXHAUSTED")
	}
	return l.append(LedgerEntry{
		Op:                  "diagnostic",
		Epoch:               last.Epoch,
		ScenarioRef:         scenarioRef,
		QueryDigest:         queryDigest,
		QueryRemaining:      last.QueryRemaining,
		DiagnosticRemaining: last.DiagnosticRemaining - 1,
	})
}

// Rotate advances the epoch, restoring budgets and clearing the probing
// latch. Rotation requires regenerating the held-out tiers at the new epoch.
func (l *Ledger) Rotate(epoch int) error {
	last := l.last()
	if epoch <= last.Epoch {
		return fmt.Errorf("rotation epoch must increase")
	}
	l.queryCounts = map[string]int{}
	return l.append(LedgerEntry{
		Op:                  "rotation",
		Epoch:               epoch,
		QueryRemaining:      l.policy.QueryBudget,
		DiagnosticRemaining: l.policy.DiagnosticBudget,
	})
}

// Serialize renders the ledger as canonical JSONL.
func (l *Ledger) Serialize() ([]byte, error) {
	var out bytes.Buffer
	for _, entry := range l.entries {
		line, err := CanonicalJSON(entry.toMap())
		if err != nil {
			return nil, err
		}
		out.Write(line)
		out.WriteByte('\n')
	}
	return out.Bytes(), nil
}

// LoadLedger parses and chain-verifies a serialized ledger.
func LoadLedger(data []byte) (*Ledger, error) {
	ledger := &Ledger{policy: DefaultCustodianPolicy(), queryCounts: map[string]int{},
		now: defaultLedgerClock, actor: defaultLedgerActor()}
	for _, line := range bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n")) {
		if len(line) == 0 {
			return nil, fmt.Errorf("empty ledger line")
		}
		var entry LedgerEntry
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&entry); err != nil {
			return nil, fmt.Errorf("ledger entry parse: %w", err)
		}
		ledger.entries = append(ledger.entries, entry)
		if entry.QueryDigest != "" && entry.Op == "query" {
			ledger.queryCounts[entry.QueryDigest]++
		}
	}
	if len(ledger.entries) == 0 {
		return nil, fmt.Errorf("ledger is empty")
	}
	if err := ledger.VerifyChain(); err != nil {
		return nil, err
	}
	return ledger, nil
}

// VerifyChain checks the hash chain and budget monotonicity end to end.
func (l *Ledger) VerifyChain() error {
	if l.entries[0].Op != "genesis" || l.entries[0].Seq != 0 {
		return fmt.Errorf("LEDGER_CHAIN_BROKEN: missing genesis")
	}
	for i := 1; i < len(l.entries); i++ {
		prevDigest, err := l.entries[i-1].digest()
		if err != nil {
			return err
		}
		entry := l.entries[i]
		if entry.PrevDigest != prevDigest || entry.Seq != l.entries[i-1].Seq+1 {
			return fmt.Errorf("LEDGER_CHAIN_BROKEN at seq %d", entry.Seq)
		}
		prev := l.entries[i-1]
		if entry.Epoch == prev.Epoch &&
			(entry.QueryRemaining > prev.QueryRemaining ||
				entry.DiagnosticRemaining > prev.DiagnosticRemaining) {
			return fmt.Errorf("BUDGET_MONOTONICITY_VIOLATION at seq %d", entry.Seq)
		}
	}
	return nil
}

// CanaryLeakFinding reports a canary token observed in a public artifact.
type CanaryLeakFinding struct {
	ScenarioID    string
	ArtifactIndex int
}

// DetectCanaryLeak scans public artifacts for secret-derived canary tokens.
// Any hit means held-out bytes escaped the protected boundary.
func DetectCanaryLeak(publicArtifacts [][]byte, canaryTokens map[string]string) []CanaryLeakFinding {
	var findings []CanaryLeakFinding
	for id, token := range canaryTokens {
		for index, artifact := range publicArtifacts {
			if bytes.Contains(artifact, []byte(token)) {
				findings = append(findings, CanaryLeakFinding{
					ScenarioID: id, ArtifactIndex: index})
			}
		}
	}
	return findings
}
