package main

import (
	"bytes"
	"testing"
)

func TestRunRejectsAnythingOutsideFixedOperation(t *testing.T) {
	for _, arguments := range [][]string{nil, {"shell"}, {"run", "--accepted-root", "x"}} {
		var stdout, stderr bytes.Buffer
		if code := run(arguments, &stdout, &stderr); code != 2 {
			t.Fatalf("arguments %q returned %d", arguments, code)
		}
	}
}
