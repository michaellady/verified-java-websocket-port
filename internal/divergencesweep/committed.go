package divergencesweep

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

// Recompute runs the whole sweep and renders the document bytes.
func Recompute(root string) ([]byte, *Document, error) {
	sweep, err := Run(root)
	if err != nil {
		return nil, nil, err
	}
	document, err := Build(sweep)
	if err != nil {
		return nil, nil, err
	}
	encoded, err := Marshal(document)
	if err != nil {
		return nil, nil, err
	}
	return encoded, document, nil
}

// Verify recomputes the document and compares it byte for byte with the
// committed one. The committed document is never read as an input to the
// recomputation, so this cannot pass by copying it.
func Verify(root string) error {
	recomputed, _, err := Recompute(root)
	if err != nil {
		return err
	}
	path := filepath.Join(root, DocumentPath)
	committed, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("committed sweep document: %w", err)
	}
	if bytes.Equal(recomputed, committed) {
		return nil
	}
	return fmt.Errorf("%s disagrees with the run reports it claims to describe: %s",
		DocumentPath, firstDifference(committed, recomputed))
}

// Write emits the recomputed document to its committed path.
func Write(root string) ([]byte, error) {
	recomputed, _, err := Recompute(root)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(root, DocumentPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, recomputed, 0o644); err != nil {
		return nil, err
	}
	return recomputed, nil
}

// firstDifference names where two renderings part company, by line, so a
// failure says what moved instead of only that something did.
func firstDifference(committed, recomputed []byte) string {
	committedLines := bytes.Split(committed, []byte("\n"))
	recomputedLines := bytes.Split(recomputed, []byte("\n"))
	limit := len(committedLines)
	if len(recomputedLines) < limit {
		limit = len(recomputedLines)
	}
	for i := 0; i < limit; i++ {
		if bytes.Equal(committedLines[i], recomputedLines[i]) {
			continue
		}
		return fmt.Sprintf("first difference at line %d: committed %q, recomputed %q",
			i+1, trimLine(committedLines[i]), trimLine(recomputedLines[i]))
	}
	return fmt.Sprintf("the first %d lines agree; the committed document has %d lines and the recomputation has %d",
		limit, len(committedLines), len(recomputedLines))
}

func trimLine(line []byte) string {
	const limit = 200
	text := string(bytes.TrimSpace(line))
	if len(text) <= limit {
		return text
	}
	return text[:limit] + "…"
}
