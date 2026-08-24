package intake

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const maxJSONBytes = 8 << 20

// DecodeStrict rejects duplicate and unknown fields, null documents, trailing
// values, and oversized inputs before returning candidate-controlled data.
func DecodeStrict(data []byte, target any) error {
	if len(data) > maxJSONBytes {
		return deny("INPUT_TOO_LARGE", "$", "JSON document exceeds 8 MiB")
	}
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return deny("NULL_JSON_DOCUMENT", "$", "top-level null is not a document")
	}
	if err := rejectDuplicateFields(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		if bytes.Contains([]byte(err.Error()), []byte("unknown field")) {
			return deny("UNKNOWN_JSON_FIELD", "$", err.Error())
		}
		return deny("INVALID_JSON", "$", err.Error())
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return deny("TRAILING_JSON_VALUE", "$", "multiple JSON values are forbidden")
		}
		return deny("INVALID_JSON", "$", err.Error())
	}
	return nil
}

func rejectDuplicateFields(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, "$", 0); err != nil {
		return err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return deny("TRAILING_JSON_VALUE", "$", fmt.Sprintf("unexpected token %v", token))
		}
		return deny("INVALID_JSON", "$", err.Error())
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder, path string, depth int) error {
	if depth > 128 {
		return deny("JSON_DEPTH_EXCEEDED", path, "JSON nesting exceeds 128")
	}
	token, err := decoder.Token()
	if err != nil {
		return deny("INVALID_JSON", path, err.Error())
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return deny("INVALID_JSON", path, err.Error())
			}
			key, ok := keyToken.(string)
			if !ok {
				return deny("INVALID_JSON", path, "object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return deny("DUPLICATE_JSON_FIELD", path+"."+key, "duplicate object field")
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder, path+"."+key, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return deny("INVALID_JSON", path, "unterminated object")
		}
	case '[':
		index := 0
		for decoder.More() {
			if err := scanJSONValue(decoder, fmt.Sprintf("%s[%d]", path, index), depth+1); err != nil {
				return err
			}
			index++
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return deny("INVALID_JSON", path, "unterminated array")
		}
	default:
		return deny("INVALID_JSON", path, "unexpected closing delimiter")
	}
	return nil
}

// CanonicalAction returns the complete action intent with only the signature
// value cleared. encoding/json is deterministic for this struct-only shape.
func CanonicalAction(action Action) []byte {
	action.Signature = ""
	data, err := json.Marshal(action)
	if err != nil {
		panic(err)
	}
	return data
}

func CanonicalJSON(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, data); err != nil {
		return nil, err
	}
	return compact.Bytes(), nil
}

func DigestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validateDigest(value string) bool {
	if len(value) != len("sha256:")+64 || value[:7] != "sha256:" {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil
}

func isEOF(err error) bool { return errors.Is(err, io.EOF) }
