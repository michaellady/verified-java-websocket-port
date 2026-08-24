package validators

import foundation "github.com/michaellady/verified-java-to-rust/foundation/foundation"

// VerifyFoundationEvidence and VerifyFoundationEvolution are narrow adapters
// to the already accepted US-002 assurance model. The protocol kernel does not
// duplicate denominator, assurance-ceiling, or minimal-staleness-cut logic.
func VerifyFoundationEvidence(data []byte) []foundation.Failure {
	return foundation.ValidateEvidence(data)
}

func VerifyFoundationEvolution(data []byte) []foundation.Failure {
	return foundation.ValidateEvolution(data)
}
