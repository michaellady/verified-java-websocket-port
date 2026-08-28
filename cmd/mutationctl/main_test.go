package main

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/mutation"
)

func TestVerifyExactCommand(t *testing.T) {
	original := verify
	t.Cleanup(func() { verify = original })
	verify = func(root string) error {
		if root != "/tmp/repo" {
			t.Fatalf("root=%q", root)
		}
		return nil
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"verify", "--repository-root", "/tmp/repo"}, &stdout, &stderr); code != 0 || stdout.String() != "PASS\n" || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestRunPlantedExactCommand(t *testing.T) {
	original := runPlanted
	t.Cleanup(func() { runPlanted = original })
	runPlanted = func(_ context.Context, cfg mutation.Config) error {
		if cfg.RepositoryRoot != "/tmp/repo" || cfg.ScratchRoot != "/tmp/scratch" || cfg.JavaExecutable != "/jdk/java" || cfg.MavenExecutable != "/maven/mvn" || cfg.MavenRepository != "/maven/repo" || cfg.CargoExecutable != "/rust/cargo" || cfg.RustcExecutable != "/rust/rustc" {
			t.Fatalf("cfg=%+v", cfg)
		}
		return nil
	}
	arguments := []string{"run-planted", "--repository-root", "/tmp/repo", "--scratch-root", "/tmp/scratch", "--java", "/jdk/java", "--maven", "/maven/mvn", "--maven-repository", "/maven/repo", "--cargo", "/rust/cargo", "--rustc", "/rust/rustc"}
	var stdout, stderr bytes.Buffer
	if code := run(arguments, &stdout, &stderr); code != 0 || stdout.String() != "PASS\n" || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestCLIRejectsUnknownRepeatedRelativeAndTrailingArguments(t *testing.T) {
	cases := [][]string{{"verify", "--repository-root", "relative"}, {"verify", "--repository-root", "/tmp/repo", "extra"}, {"verify", "--other", "/tmp/repo"}, {"run-planted", "--repository-root", "/tmp/repo", "--repository-root", "/tmp/scratch", "--java", "/jdk/java", "--maven", "/maven/mvn", "--maven-repository", "/maven/repo", "--cargo", "/rust/cargo", "--rustc", "/rust/rustc"}}
	for _, arguments := range cases {
		var stdout, stderr bytes.Buffer
		if code := run(arguments, &stdout, &stderr); code != 64 || stdout.Len() != 0 || stderr.String() != usage {
			t.Fatalf("args=%v code=%d stdout=%q stderr=%q", arguments, code, stdout.String(), stderr.String())
		}
	}
}

func TestCLIFailsClosed(t *testing.T) {
	original := verify
	t.Cleanup(func() { verify = original })
	verify = func(string) error { return errors.New("drift") }
	var stdout, stderr bytes.Buffer
	if code := run([]string{"verify", "--repository-root", "/tmp/repo"}, &stdout, &stderr); code != 1 || stdout.Len() != 0 || stderr.String() != "mutation verify failed: drift\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
