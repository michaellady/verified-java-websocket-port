package corpora

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func compileSchema(schemasDir, name string) (*jsonschema.Schema, error) {
	content, err := os.ReadFile(filepath.Join(schemasDir, name))
	if err != nil {
		return nil, err
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(content))
	if err != nil {
		return nil, err
	}
	compiler := jsonschema.NewCompiler()
	resource := "https://verified-java-websocket-port.invalid/" + name
	if err := compiler.AddResource(resource, value); err != nil {
		return nil, err
	}
	return compiler.Compile(resource)
}

func validateJSONLLines(schema *jsonschema.Schema, path string, fail func(code, path, detail string)) {
	raw, err := os.ReadFile(path)
	if err != nil {
		fail("SCHEMA_TARGET_UNREADABLE", path, err.Error())
		return
	}
	for index, line := range bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n")) {
		value, err := jsonschema.UnmarshalJSON(bytes.NewReader(line))
		if err != nil {
			fail("SCHEMA_TARGET_NOT_JSON", fmt.Sprintf("%s:%d", path, index+1), err.Error())
			continue
		}
		if err := schema.Validate(value); err != nil {
			fail("SCHEMA_VIOLATION", fmt.Sprintf("%s:%d", path, index+1), err.Error())
		}
	}
}

func validateJSONFile(schema *jsonschema.Schema, path string, fail func(code, path, detail string)) {
	raw, err := os.ReadFile(path)
	if err != nil {
		fail("SCHEMA_TARGET_UNREADABLE", path, err.Error())
		return
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		fail("SCHEMA_TARGET_NOT_JSON", path, err.Error())
		return
	}
	if err := schema.Validate(value); err != nil {
		fail("SCHEMA_VIOLATION", path, err.Error())
	}
}

// ValidateCorpusSchemas validates every committed corpus artifact — public
// and handshake lines, all four manifests, the protected held-out lines, and
// the calibration document — against the strict schemas.
func ValidateCorpusSchemas(schemasDir, root, protectedRoot string) ([]Finding, error) {
	var findings []Finding
	fail := func(code, path, detail string) {
		findings = append(findings, Finding{Code: code, Path: path, Detail: detail})
	}

	scenarioSchema, err := compileSchema(schemasDir, "corpus-scenario-1.0.0.schema.json")
	if err != nil {
		return nil, fmt.Errorf("compile scenario schema: %w", err)
	}
	handshakeSchema, err := compileSchema(schemasDir, "corpus-handshake-case-1.0.0.schema.json")
	if err != nil {
		return nil, fmt.Errorf("compile handshake schema: %w", err)
	}
	manifestSchema, err := compileSchema(schemasDir, "corpus-manifest-1.0.0.schema.json")
	if err != nil {
		return nil, fmt.Errorf("compile manifest schema: %w", err)
	}
	calibrationSchema, err := compileSchema(schemasDir, "corpus-calibration-1.0.0.schema.json")
	if err != nil {
		return nil, fmt.Errorf("compile calibration schema: %w", err)
	}

	validateJSONLLines(scenarioSchema,
		filepath.Join(root, repoCorporaDir, "public/scenarios.jsonl"), fail)
	validateJSONLLines(handshakeSchema,
		filepath.Join(root, repoCorporaDir, "handshake/cases.jsonl"), fail)
	if protectedRoot != "" {
		validateJSONLLines(scenarioSchema,
			filepath.Join(protectedRoot, protectedHiddenLines), fail)
		validateJSONLLines(scenarioSchema,
			filepath.Join(protectedRoot, protectedSealedLines), fail)
	}
	for _, tier := range []string{"public", "handshake", "hidden", "sealed"} {
		validateJSONFile(manifestSchema,
			filepath.Join(root, repoCorporaDir, tier, "manifest.json"), fail)
	}
	calibrationPath := filepath.Join(root, "evidence/corpus-calibration.json")
	if _, err := os.Stat(calibrationPath); err == nil {
		validateJSONFile(calibrationSchema, calibrationPath, fail)
	}
	return findings, nil
}
