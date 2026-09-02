package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func root(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate this test file")
	}
	path, err := filepath.Abs(filepath.Join(filepath.Dir(file), "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func capture(t *testing.T, args []string) (string, error) {
	t.Helper()
	temp, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer temp.Close()
	runErr := run(args, temp)
	data, err := os.ReadFile(temp.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(data), runErr
}

func TestVerifyReportsTheDerivedCoverageAsAFraction(t *testing.T) {
	out, err := capture(t, []string{"verify", "-repo", root(t)})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	for _, want := range []string{
		"catalog=us023-formal-obligations denominator=24",
		"java_bindings_connected=4/24",
		"java_bindings_partial=2/24",
		"java_bindings_disconnected=18/24",
		"java_mutation_sensitive=6/24",
		"java_bindings_at_required_strength=0/24",
		"refinement=0/24",
		"aggregate=0/24",
		"assurance=OWNER_ATTESTED_NOT_INDEPENDENT independent_review_claimed=false",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("verify output does not report %q:\n%s", want, out)
		}
	}
}

func TestVerifyRejectsAnEditedProjection(t *testing.T) {
	// Copy the repository artifacts into a scratch tree, edit a coverage number
	// in the projection, and require the read-only verifier to reject it.
	source := root(t)
	scratch := t.TempDir()
	for _, relative := range []string{
		"assurance/formal/java-binding-spec.json",
		"assurance/formal/obligation-catalog.json",
		"evidence/java/formal-bindings/receipt.json",
		"evidence/java/formal-bindings/coverage-projection.json",
	} {
		data, err := os.ReadFile(filepath.Join(source, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(scratch, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := capture(t, []string{"verify", "-repo", scratch}); err != nil {
		t.Fatalf("the unedited copy must verify: %v", err)
	}

	projectionPath := filepath.Join(scratch, "evidence", "java", "formal-bindings", "coverage-projection.json")
	data, err := os.ReadFile(projectionPath)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(data), `"java_bindings_connected": 4`, `"java_bindings_connected": 24`, 1)
	if edited == string(data) {
		t.Fatal("the projection does not contain the numerator this test edits")
	}
	if err := os.WriteFile(projectionPath, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := capture(t, []string{"verify", "-repo", scratch}); err == nil {
		t.Fatal("an inflated numerator must be rejected by the read-only verifier")
	}
}

func TestVerifyRejectsASubstitutedCatalog(t *testing.T) {
	source := root(t)
	scratch := t.TempDir()
	for _, relative := range []string{
		"assurance/formal/java-binding-spec.json",
		"assurance/formal/obligation-catalog.json",
		"evidence/java/formal-bindings/receipt.json",
		"evidence/java/formal-bindings/coverage-projection.json",
	} {
		data, err := os.ReadFile(filepath.Join(source, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(scratch, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	catalogPath := filepath.Join(scratch, "assurance", "formal", "obligation-catalog.json")
	data, err := os.ReadFile(catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	// One added byte of insignificant whitespace: the denominator's content
	// identity must be what is checked, not its shape or its presence.
	if err := os.WriteFile(catalogPath, append(data, ' '), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := capture(t, []string{"verify", "-repo", scratch}); err == nil {
		t.Fatal("a catalog that is not the pinned bytes must be rejected")
	}
}

func TestUnknownSubcommandFails(t *testing.T) {
	if _, err := capture(t, []string{"observe-ish"}); err == nil {
		t.Fatal("an unknown subcommand must fail")
	}
	if _, err := capture(t, nil); err == nil {
		t.Fatal("no subcommand must fail")
	}
}
