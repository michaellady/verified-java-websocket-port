package corpora

import (
	"strings"
	"testing"
)

// The canonical writer must byte-match java-oracle's StrictJson.write so that
// request digests computed here bind the identical canonical form the oracle
// recomputes: lexicographically sorted keys, no whitespace, plain integers,
// and the exact escape set (\" \\ \b \f \n \r \t and \u%04x below 0x20).
func TestCanonicalJSONMatchesStrictJsonRules(t *testing.T) {
	cases := []struct {
		name  string
		value any
		want  string
	}{
		{"sorted keys", map[string]any{"b": 1, "a": 2}, `{"a":2,"b":1}`},
		{"nested", map[string]any{"z": []any{map[string]any{"y": "x"}}}, `{"z":[{"y":"x"}]}`},
		{"escapes", map[string]any{"s": "a\"b\\c\nd\te\rf\bg\fh"}, `{"s":"a\"b\\c\nd\te\rf\bg\fh"}`},
		{"control", map[string]any{"s": "\x01"}, `{"s":"\u0001"}`},
		{"unicode raw", map[string]any{"s": "héllo"}, `{"s":"héllo"}`},
		{"bool null", map[string]any{"t": true, "n": nil}, `{"n":null,"t":true}`},
		{"int", map[string]any{"i": 42}, `{"i":42}`},
		{"empty containers", map[string]any{"a": []any{}, "o": map[string]any{}}, `{"a":[],"o":{}}`},
	}
	for _, tc := range cases {
		got, err := CanonicalJSON(tc.value)
		if err != nil {
			t.Fatalf("%s: CanonicalJSON error: %v", tc.name, err)
		}
		if string(got) != tc.want {
			t.Fatalf("%s: got %s want %s", tc.name, got, tc.want)
		}
	}
}

func TestCanonicalJSONRejectsUnsupportedValues(t *testing.T) {
	if _, err := CanonicalJSON(map[string]any{"f": 1.5}); err == nil {
		t.Fatal("non-integer numbers must be rejected: the oracle protocol carries only integers")
	}
	if _, err := CanonicalJSON(map[string]any{"c": make(chan int)}); err == nil {
		t.Fatal("unsupported Go values must fail closed")
	}
}

func TestDigestSHA256IsLowercaseHexWithPrefix(t *testing.T) {
	digest := DigestSHA256([]byte("abc"))
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != len("sha256:")+64 {
		t.Fatalf("digest form invalid: %q", digest)
	}
	if digest != "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("sha256(abc) mismatch: %q", digest)
	}
}
