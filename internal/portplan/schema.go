package portplan

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// SchemaByDocument names the strict schema each frozen document must satisfy.
var SchemaByDocument = map[string]string{
	ManifestDocument:         "java-intake-manifest-1.0.0.schema.json",
	SurfaceInventoryDocument: "surface-inventory-1.0.0.schema.json",
	MigrationMapDocument:     "semantic-id-migration-map-1.1.0.schema.json",
	SeamDossierDocument:      "port-seam-dossier-1.0.0.schema.json",
	CompatibilityDocument:    "compatibility-surface-1.0.0.schema.json",
	CutoverDocument:          "cutover-contract-1.0.0.schema.json",
}

// ValidateAgainstSchema validates one frozen document against its schema and returns the schema
// failure messages. An empty slice with a nil error means the document conforms.
func ValidateAgainstSchema(root, document string) ([]string, error) {
	schemaName, known := SchemaByDocument[document]
	if !known {
		return nil, fmt.Errorf("no schema registered for %s", document)
	}
	schemaPath := filepath.Join(root, "schemas", schemaName)
	schemaContent, err := os.ReadFile(schemaPath)
	if err != nil {
		return nil, err
	}
	schemaValue, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaContent))
	if err != nil {
		return nil, err
	}
	compiler := jsonschema.NewCompiler()
	resourceURL := "https://verified-java-websocket-port.invalid/" + schemaName
	if err := compiler.AddResource(resourceURL, schemaValue); err != nil {
		return nil, err
	}
	schema, err := compiler.Compile(resourceURL)
	if err != nil {
		return nil, err
	}

	documentContent, err := os.ReadFile(filepath.Join(root, EvidenceDirectory, document))
	if err != nil {
		return nil, err
	}
	documentValue, err := jsonschema.UnmarshalJSON(bytes.NewReader(documentContent))
	if err != nil {
		return nil, err
	}
	if err := schema.Validate(documentValue); err != nil {
		var validationError *jsonschema.ValidationError
		if ok := asValidationError(err, &validationError); ok {
			return flattenValidationError(validationError), nil
		}
		return []string{err.Error()}, nil
	}
	return nil, nil
}

func asValidationError(err error, target **jsonschema.ValidationError) bool {
	if candidate, ok := err.(*jsonschema.ValidationError); ok {
		*target = candidate
		return true
	}
	return false
}

func flattenValidationError(err *jsonschema.ValidationError) []string {
	var messages []string
	var walk func(node *jsonschema.ValidationError)
	walk = func(node *jsonschema.ValidationError) {
		if node == nil {
			return
		}
		if len(node.Causes) == 0 {
			messages = append(messages, node.Error())
			return
		}
		for _, cause := range node.Causes {
			walk(cause)
		}
	}
	walk(err)
	if len(messages) == 0 {
		messages = append(messages, err.Error())
	}
	sort.Strings(messages)
	if len(messages) > 25 {
		messages = messages[:25]
	}
	return messages
}
