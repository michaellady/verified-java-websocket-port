package protocol

import "time"

// JavaToRustPolicy returns the explicit v1 policy input. Callers may construct
// a stricter Policy; the runner never infers semantic or assurance policy.
func JavaToRustPolicy() Policy {
	return Policy{
		Version:             "java-rust-assurance-1.0.0",
		Company:             "open-source-projects",
		Project:             "verified-java-to-rust-port",
		AllowedNodeKinds:    []string{"source-pin", "java-oracle", "rust-port", "evidence", "claim", "review", "attestation"},
		AllowedEdgeKinds:    []string{"depends-on", "supports", "attests", "pins"},
		TransientErrorTypes: []string{"NETWORK_DENIED", "WORKER_INTERRUPTED", "STORAGE_UNAVAILABLE", "LEASE_EXPIRED"},
		SemanticErrorTypes:  []string{"SEMANTIC_INCONSISTENCY", "ORACLE_MISMATCH"},
		SecurityErrorTypes:  []string{"AUTHORIZATION_DENIED", "REVOKED_KEY", "ROLE_CONFLICT", "PROTECTED_DISCLOSURE"},
		IntegrityErrorTypes: []string{"CORRUPT_CACHE", "DIGEST_MISMATCH", "PARTIAL_PUBLICATION"},
		LSPErrorTypes:       []string{"LSP_NAVIGATION_FAILURE"},
		IncompatibleRoles: map[string][]string{
			"method-schema-steward":     {"port-implementer", "oracle-held-out-custodian", "release-attestor"},
			"port-implementer":          {"method-schema-steward", "oracle-held-out-custodian", "release-attestor"},
			"oracle-held-out-custodian": {"method-schema-steward", "port-implementer", "release-attestor"},
			"release-attestor":          {"method-schema-steward", "port-implementer", "oracle-held-out-custodian"},
		},
		RequiredStages:           []string{"ingest", "verify", "attest", "publish"},
		RequiredAttestationRoles: []string{"independent-verifier-a", "independent-verifier-b"},
		ActionRoles: map[string][]string{
			"START_STAGE:ingest": {"port-implementer"}, "COMPLETE_ATTEMPT:ingest": {"port-implementer"},
			"START_STAGE:verify": {"port-implementer"}, "COMPLETE_ATTEMPT:verify": {"port-implementer"},
			"START_STAGE:attest": {"independent-verifier-a", "independent-verifier-b"}, "COMPLETE_ATTEMPT:attest": {"independent-verifier-a", "independent-verifier-b"},
			"START_STAGE:publish": {"release-attestor"}, "COMPLETE_ATTEMPT:publish": {"release-attestor"},
			"VERIFY_CHECKPOINT:": {"independent-verifier-a", "independent-verifier-b"},
			"PROMOTE:":           {"release-attestor"}, "CANCEL:": {"port-implementer", "release-attestor"},
			"SUPERSEDE:": {"release-attestor"}, "AUTHORIZE_RETRY:ingest": {"independent-verifier-a", "independent-verifier-b"},
			"AUTHORIZE_RETRY:verify":  {"independent-verifier-a", "independent-verifier-b"},
			"AUTHORIZE_RETRY:attest":  {"independent-verifier-a", "independent-verifier-b"},
			"AUTHORIZE_RETRY:publish": {"independent-verifier-a", "independent-verifier-b"},
		},
		AllowedSnapshotTransitions: map[string][]string{
			"PROPOSED":   {"QUALIFIED", "BLOCKED", "REVOKED"},
			"QUALIFIED":  {"CANDIDATE", "BLOCKED", "STALE", "REVOKED"},
			"CANDIDATE":  {"ACCEPTED", "BLOCKED", "STALE", "REVOKED"},
			"ACCEPTED":   {"PUBLISHED", "STALE", "SUPERSEDED", "REVOKED"},
			"PUBLISHED":  {"STALE", "SUPERSEDED", "REVOKED"},
			"BLOCKED":    {"PROPOSED", "REVOKED"},
			"STALE":      {"PROPOSED", "SUPERSEDED", "REVOKED"},
			"SUPERSEDED": {},
			"REVOKED":    {},
		},
		MaximumAuthorizationAgeSeconds: int((24 * time.Hour) / time.Second),
		MaximumAttemptsPerStage:        3,
		MaximumBackoffSeconds:          int((30 * time.Second) / time.Second),
	}
}

func DispositionFor(policy Policy, errorType string) Disposition {
	switch {
	case Contains(policy.TransientErrorTypes, errorType):
		return Retry
	case Contains(policy.LSPErrorTypes, errorType):
		return DegradeNonAssurance
	case Contains(policy.SecurityErrorTypes, errorType), Contains(policy.IntegrityErrorTypes, errorType):
		return Quarantine
	case Contains(policy.SemanticErrorTypes, errorType):
		return Block
	default:
		return Block
	}
}
