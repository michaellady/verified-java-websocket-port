package benchplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"
)

const bindingReceiptSchema = "vjwp-binding-evidence-receipt/1.0.0"

type evidenceReceiptReference struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

type bindingEvidenceReceipt struct {
	Schema       string `json:"schema"`
	EvidenceType string `json:"evidence_type"`
	Environment  struct {
		ID       string `json:"id"`
		Role     string `json:"role"`
		Document string `json:"document"`
	} `json:"environment"`
	Field struct {
		Path  string          `json:"path"`
		Value json.RawMessage `json:"value"`
	} `json:"field"`
	CapturedAt string `json:"captured_at"`
	Source     struct {
		Kind    string `json:"kind"`
		Locator string `json:"locator"`
		Digest  string `json:"digest"`
	} `json:"source"`
}

var placeholderIdentityPattern = regexp.MustCompile(`(?i)(^|[^a-z0-9])(placeholder|synthetic|test[_ -]?only|fabricated|dummy|example|not[_ -]?measured|owner[_ -]?decision[_ -]?pending|tbd|todo|fake)([^a-z0-9]|$)`)

var ownerAttestedReceiptFields = map[string]bool{
	"confirmation|host_identity.instance_type":        true,
	"confirmation|host_identity.region":               true,
	"confirmation|host_identity.ami_id":               true,
	"confirmation|host_identity.ami_name":             true,
	"confirmation|tool_identities.terraform":          true,
	"confirmation|tool_identities.go_toolchain":       true,
	"confirmation|tool_identities.runner_build_flags": true,
	"confirmation|tool_identities.yq":                 true,
}

func validateBindingReceipt(root, document, environmentID, role, fieldPath string, field environmentField, allowTestOnly bool) (bool, []string) {
	var failures []string
	fail := func(format string, args ...any) { failures = append(failures, fmt.Sprintf(format, args...)) }
	if field.EvidenceReceipt == nil {
		fail("BOUND identity requires an evidence_receipt path and digest")
		return false, failures
	}
	reference := field.EvidenceReceipt
	expectedPath := fmt.Sprintf("benchmarks/evidence/receipts/%s/%s.json", role, fieldPath)
	if reference.Path != expectedPath {
		fail("evidence receipt path %q must equal canonical path %q", reference.Path, expectedPath)
		return false, failures
	}
	if !validDigest(reference.Digest) {
		fail("evidence receipt reference requires a nonzero sha256 digest")
	}
	if field.EvidenceDigest != reference.Digest {
		fail("evidence_digest must equal evidence_receipt.digest")
	}

	receiptPath := filepath.Join(root, filepath.FromSlash(reference.Path))
	info, err := os.Lstat(receiptPath)
	if err != nil {
		fail("cannot reopen evidence receipt: %v", err)
		return false, failures
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		fail("evidence receipt must be a regular, non-symlink file")
		return false, failures
	}
	content, err := os.ReadFile(receiptPath)
	if err != nil {
		fail("cannot read evidence receipt: %v", err)
		return false, failures
	}
	actualDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(content))
	if actualDigest != reference.Digest {
		fail("evidence receipt digest mismatch: declared %s, actual %s", reference.Digest, actualDigest)
	}

	var receipt bindingEvidenceReceipt
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		fail("evidence receipt strict decode failed: %v", err)
		return false, failures
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		fail("evidence receipt has trailing JSON content")
		return false, failures
	}
	if receipt.Schema != bindingReceiptSchema {
		fail("evidence receipt schema %q must equal %q", receipt.Schema, bindingReceiptSchema)
	}
	if receipt.Environment.ID != environmentID || receipt.Environment.Role != role || receipt.Environment.Document != document {
		fail("evidence receipt environment (%q, %q, %q) does not match (%q, %q, %q)",
			receipt.Environment.ID, receipt.Environment.Role, receipt.Environment.Document,
			environmentID, role, document)
	}
	if receipt.Field.Path != fieldPath {
		fail("evidence receipt field %q does not match %q", receipt.Field.Path, fieldPath)
	}
	if !sameJSONValue(receipt.Field.Value, field.Value) {
		fail("evidence receipt value does not match the environment field value")
	}
	if parsed, err := time.Parse(time.RFC3339, receipt.CapturedAt); err != nil || !strings.HasSuffix(receipt.CapturedAt, "Z") || parsed.IsZero() {
		fail("evidence receipt captured_at must be a nonzero UTC RFC3339 timestamp")
	}
	if strings.TrimSpace(receipt.Source.Locator) == "" || !validDigest(receipt.Source.Digest) {
		fail("evidence receipt source requires a locator and nonzero sha256 digest")
	}

	testOnly := receipt.EvidenceType == "TEST_ONLY"
	expectedType, expectedSource := expectedReceiptType(role, fieldPath)
	if testOnly {
		if !allowTestOnly {
			fail("TEST_ONLY evidence receipts are rejected by production verification")
		}
		if receipt.Source.Kind != "TEST_FIXTURE" {
			fail("TEST_ONLY evidence receipt source kind must be TEST_FIXTURE")
		}
	} else {
		if receipt.EvidenceType != expectedType {
			fail("evidence_type %q must equal %q for this role and field", receipt.EvidenceType, expectedType)
		}
		if receipt.Source.Kind != expectedSource {
			fail("source kind %q must equal %q for evidence_type %q", receipt.Source.Kind, expectedSource, expectedType)
		}
	}
	return testOnly, failures
}

func expectedReceiptType(role, fieldPath string) (string, string) {
	if ownerAttestedReceiptFields[role+"|"+fieldPath] {
		return "OWNER_ATTESTED_DECISION", "OWNER_ATTESTATION"
	}
	if strings.HasPrefix(fieldPath, "host_identity.") {
		return "HOST_OBSERVATION", "HOST_PROBE"
	}
	return "TOOL_PROVENANCE", "TOOL_PROVENANCE"
}

func sameJSONValue(left, right json.RawMessage) bool {
	var leftValue, rightValue any
	if json.Unmarshal(left, &leftValue) != nil || json.Unmarshal(right, &rightValue) != nil {
		return false
	}
	return reflect.DeepEqual(leftValue, rightValue)
}

func containsPlaceholderIdentity(value any) bool {
	switch typed := value.(type) {
	case string:
		return placeholderIdentityPattern.MatchString(typed)
	case map[string]any:
		for _, child := range typed {
			if containsPlaceholderIdentity(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsPlaceholderIdentity(child) {
				return true
			}
		}
	}
	return false
}
