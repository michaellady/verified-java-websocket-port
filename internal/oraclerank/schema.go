package oraclerank

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// SchemaPath is the committed JSON Schema for the adjudication register.
//
// Every other evidence document in this tree had a schema and this one did not.
// A schema that is only a document is worth little, so ValidateAgainstSchema is
// wired into cmd/oraclerankctl --check: the register is validated against it on
// every run, and a register that does not conform is a failure with an exit
// code rather than a note.
const SchemaPath = "schemas/oracle-hierarchy-adjudication-register-1.0.0.schema.json"

// ValidateAgainstSchema compiles the committed schema and validates the
// committed register against it. It fails closed on a missing or unparseable
// schema: a validation that cannot run must not read as a validation that
// passed. That is the F006 shape -- absence standing in for a result -- and it
// is refused here explicitly.
func ValidateAgainstSchema(root string) error {
	schemaBytes, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(SchemaPath)))
	if err != nil {
		return fmt.Errorf("read %s: %w (the register's schema must be present; a validation that cannot run is not a validation that passed)", SchemaPath, err)
	}
	schemaValue, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaBytes))
	if err != nil {
		return fmt.Errorf("%s is not readable as JSON: %w", SchemaPath, err)
	}
	compiler := jsonschema.NewCompiler()
	resourceURL := "https://verified-java-websocket-port.invalid/" + filepath.Base(SchemaPath)
	if err := compiler.AddResource(resourceURL, schemaValue); err != nil {
		return fmt.Errorf("%s: add resource: %w", SchemaPath, err)
	}
	schema, err := compiler.Compile(resourceURL)
	if err != nil {
		return fmt.Errorf("%s: compile: %w", SchemaPath, err)
	}

	docBytes, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(RegisterPath)))
	if err != nil {
		return fmt.Errorf("read %s: %w", RegisterPath, err)
	}
	docValue, err := jsonschema.UnmarshalJSON(bytes.NewReader(docBytes))
	if err != nil {
		return fmt.Errorf("%s is not readable as JSON: %w", RegisterPath, err)
	}
	if err := schema.Validate(docValue); err != nil {
		var ve *jsonschema.ValidationError
		if errors.As(err, &ve) {
			causes := flattenSchemaError(ve)
			sort.Strings(causes)
			if len(causes) > 12 {
				causes = append(causes[:12], fmt.Sprintf("... and %d more", len(causes)-12))
			}
			return fmt.Errorf("%s does not satisfy %s:\n  %v", RegisterPath, SchemaPath, causes)
		}
		return fmt.Errorf("%s does not satisfy %s: %w", RegisterPath, SchemaPath, err)
	}
	return nil
}

// flattenSchemaError turns a nested validation error into one line per leaf
// cause, so the failure names the field rather than the document.
func flattenSchemaError(ve *jsonschema.ValidationError) []string {
	if len(ve.Causes) == 0 {
		return []string{fmt.Sprintf("%v: %v", ve.InstanceLocation, ve.ErrorKind)}
	}
	var out []string
	for _, cause := range ve.Causes {
		out = append(out, flattenSchemaError(cause)...)
	}
	return out
}
