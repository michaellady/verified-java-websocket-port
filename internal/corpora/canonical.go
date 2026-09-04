// Package corpora calibrates the US-005 public, hidden, sealed, and handshake
// corpora: language-independent scenarios with reference-model expectations,
// deterministic seeded generation, sealed-tier commitment mechanics, and
// fail-closed calibration validation.
package corpora

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// CanonicalJSON writes a value in the exact canonical form java-oracle's
// StrictJson.write produces: lexicographically sorted object keys, no
// whitespace, plain integers, and the StrictJson escape set. Digests computed
// over this form bind the identical bytes the oracle recomputes.
func CanonicalJSON(value any) ([]byte, error) {
	var out strings.Builder
	if err := appendCanonical(&out, value); err != nil {
		return nil, err
	}
	return []byte(out.String()), nil
}

func appendCanonical(out *strings.Builder, value any) error {
	switch typed := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if typed {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case int:
		fmt.Fprintf(out, "%d", typed)
	case int64:
		fmt.Fprintf(out, "%d", typed)
	case string:
		appendCanonicalString(out, typed)
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			appendCanonicalString(out, key)
			out.WriteByte(':')
			if err := appendCanonical(out, typed[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	case []any:
		out.WriteByte('[')
		for i, item := range typed {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := appendCanonical(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case []map[string]any:
		items := make([]any, len(typed))
		for i, item := range typed {
			items[i] = item
		}
		return appendCanonical(out, items)
	default:
		return fmt.Errorf("unsupported canonical JSON value type %T", value)
	}
	return nil
}

func appendCanonicalString(out *strings.Builder, value string) {
	out.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(out, `\u%04x`, r)
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
}

// DigestSHA256 returns the repository's standard sha256:<hex> digest form.
func DigestSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
