package formal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	vendorprotocol "github.com/michaellady/verified-java-to-rust/foundation/protocol"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func decodeStrict(data []byte, target any) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("INVALID_UTF8: JSON input is not valid UTF-8")
	}
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return fmt.Errorf("NULL_JSON_DOCUMENT: top-level null is not a document")
	}
	return vendorprotocol.DecodeStrict(data, target)
}

func decodeReason(err error) string {
	message := err.Error()
	switch {
	case strings.Contains(message, "DUPLICATE_JSON_FIELD"), strings.Contains(message, "duplicate JSON object key"):
		return "DUPLICATE_JSON_MEMBER"
	case strings.Contains(message, "UNKNOWN_JSON_FIELD"), strings.Contains(message, "unknown field"):
		return "UNKNOWN_JSON_MEMBER"
	case strings.Contains(message, "TRAILING_JSON_VALUE"), strings.Contains(message, "multiple JSON values"):
		return "TRAILING_JSON_VALUE"
	case strings.Contains(message, "NULL_JSON_DOCUMENT"):
		return "NULL_JSON_DOCUMENT"
	case strings.Contains(message, "JSON_DEPTH_EXCEEDED"):
		return "JSON_DEPTH_EXCEEDED"
	case strings.Contains(message, "INVALID_UTF8"):
		return "INVALID_UTF8"
	default:
		return "INVALID_JSON"
	}
}

func compileSchema(data []byte, schemaPath string) (*jsonschema.Schema, error) {
	var strict any
	if err := decodeStrict(data, &strict); err != nil {
		return nil, err
	}
	var resource any
	if err := json.Unmarshal(data, &resource); err != nil {
		return nil, err
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	compiler.AssertContent()
	url := "mem:///" + schemaPath
	if err := compiler.AddResource(url, resource); err != nil {
		return nil, err
	}
	return compiler.Compile(url)
}

func schemaMessages(err error) []string {
	validationError, ok := err.(*jsonschema.ValidationError)
	if !ok {
		return []string{err.Error()}
	}
	var messages []string
	var walk func(*jsonschema.ValidationError)
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
	walk(validationError)
	sort.Strings(messages)
	if len(messages) > 12 {
		messages = messages[:12]
	}
	return messages
}
