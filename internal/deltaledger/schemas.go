package deltaledger

// JSON-SCHEMA VALIDATION AS A GATE, NOT AS A TEST.
//
// ROUND-2 FINDING 4, and it is round-1 finding 3 recurring one layer up. Round
// one moved the census and observation RULES out of `_test.go` files into
// production code behind VerifyIntegrity, because `rust/Makefile`'s
// `ledger-gates` target runs `deltaledgerctl --check` and no `go test` at all,
// there is no root Makefile, and no workflow runs Go tests. Two rules did not
// make that move: the JSON-schema validation of the new evidence documents
// (integrity_test.go) and the observation envelope and uniqueness checks
// (observations_test.go). So an unknown census field, or a drifted observation
// `$schema` or `evidence_kind`, passed production `--check`.
//
// Reproduced before this file existed: adding
// `"an_unknown_field_the_schema_forbids": "present"` to a census row and
// rewriting the observation set's `$schema` to a file that does not exist and
// its `evidence_kind` to "not-an-observed-disagreement-set" left both
// `go run ./cmd/deltaledgerctl --root . --check` and
// `make -C rust ledger-gates` at exit 0.
//
// The envelope and uniqueness rules moved into ReadObservations, which every
// caller goes through. The schema validation is here, called by VerifyIntegrity.
// The tests now call these exported functions, so a rule cannot be strong in the
// test binary and absent from the gate.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// SchemaBinding pairs a committed evidence document with the schema it must
// validate against.
type SchemaBinding struct {
	Document string
	Schema   string
}

// EvidenceSchemaBindings are the documents this package owns and regenerates.
// Every one of them is validated by the GATE.
func EvidenceSchemaBindings() []SchemaBinding {
	return []SchemaBinding{
		{Document: LedgerRelativePath, Schema: LedgerSchemaRelativePath},
		{Document: CensusRelativePath, Schema: CensusSchemaRelativePath},
		{Document: SupersessionsRelativePath, Schema: SupersessionsSchemaRelativePath},
		{Document: ObservationsRelativePath, Schema: ObservationsSchemaRelativePath},
		{Document: OwnerDecisionManifestRelativePath, Schema: OwnerDecisionManifestSchemaRelativePath},
		{Document: LegacyAdjudicationsRelativePath, Schema: LegacyAdjudicationsSchemaRelativePath},
	}
}

// VerifyEvidenceDocumentSchemas validates every committed document this package
// owns against its declared schema, reporting all failures rather than the
// first.
func VerifyEvidenceDocumentSchemas(root string) error {
	var problems []string
	for _, binding := range EvidenceSchemaBindings() {
		if err := validateAgainstSchema(root, binding); err != nil {
			problems = append(problems, err.Error())
		}
	}
	sort.Strings(problems)
	if len(problems) != 0 {
		return fmt.Errorf("evidence document schemas (%d problem(s)):\n  %s",
			len(problems), strings.Join(problems, "\n  "))
	}
	return nil
}

func validateAgainstSchema(root string, binding SchemaBinding) error {
	schemaRaw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(binding.Schema)))
	if err != nil {
		return fmt.Errorf("%s names schema %s, which cannot be read: %v", binding.Document, binding.Schema, err)
	}
	schemaDocument, err := jsonschema.UnmarshalJSON(strings.NewReader(string(schemaRaw)))
	if err != nil {
		return fmt.Errorf("%s does not decode as JSON: %v", binding.Schema, err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(binding.Schema, schemaDocument); err != nil {
		return fmt.Errorf("%s cannot be added to the compiler: %v", binding.Schema, err)
	}
	compiled, err := compiler.Compile(binding.Schema)
	if err != nil {
		return fmt.Errorf("%s does not compile: %v", binding.Schema, err)
	}
	documentRaw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(binding.Document)))
	if err != nil {
		return fmt.Errorf("%s cannot be read: %v", binding.Document, err)
	}
	instance, err := jsonschema.UnmarshalJSON(strings.NewReader(string(documentRaw)))
	if err != nil {
		return fmt.Errorf("%s does not decode as JSON: %v", binding.Document, err)
	}
	if err := compiled.Validate(instance); err != nil {
		return fmt.Errorf("%s does not validate against %s: %v", binding.Document, binding.Schema, err)
	}
	return nil
}
