package lab

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

func TestAcceptedRootLoadsVerifiedBytesAndMaterializesDeterministically(t *testing.T) {
	store := filepath.Join(t.TempDir(), "store")
	objects := []intake.Object{
		{ID: "z-object", Bytes: []byte("z")},
		{ID: "a-object", Bytes: []byte("alpha")},
	}
	for index := range objects {
		objects[index].Digest = intake.DigestBytes(objects[index].Bytes)
	}
	rootDigest, err := intake.PromoteDirectory(store, objects)
	if err != nil {
		t.Fatal(err)
	}
	root, err := LoadAcceptedRoot(store, rootDigest)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := root.Object("a-object")
	if !ok || string(got) != "alpha" {
		t.Fatalf("unexpected object: %q %v", got, ok)
	}
	got[0] = 'X'
	if again, _ := root.Object("a-object"); string(again) != "alpha" {
		t.Fatal("accepted root exposed mutable bytes")
	}
	destination := filepath.Join(t.TempDir(), "materialized")
	materialized, err := root.Materialize(destination)
	if err != nil || materialized != rootDigest {
		t.Fatalf("materialize = %q, %v", materialized, err)
	}
	if _, err := LoadAcceptedRoot(destination, rootDigest); err != nil {
		t.Fatalf("materialized root did not verify: %v", err)
	}
}

func TestAcceptedRootRejectsLinkedAndMutatedMembers(t *testing.T) {
	for _, member := range []string{"manifest", "object"} {
		for _, link := range []string{"symlink", "hardlink"} {
			t.Run(member+"-"+link, func(t *testing.T) {
				store := filepath.Join(t.TempDir(), "store")
				object := intake.Object{ID: "source", Bytes: []byte("trusted")}
				object.Digest = intake.DigestBytes(object.Bytes)
				root, err := intake.PromoteDirectory(store, []intake.Object{object})
				if err != nil {
					t.Fatal(err)
				}
				rootPath := filepath.Join(store, "accepted", root[7:])
				target := filepath.Join(rootPath, "manifest.json")
				if member == "object" {
					target = filepath.Join(rootPath, "objects", object.Digest[7:])
				}
				bytes, err := os.ReadFile(target)
				if err != nil {
					t.Fatal(err)
				}
				external := filepath.Join(t.TempDir(), "outside")
				if err := os.WriteFile(external, bytes, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(target); err != nil {
					t.Fatal(err)
				}
				if link == "symlink" {
					err = os.Symlink(external, target)
				} else {
					err = os.Link(external, target)
				}
				if err != nil {
					t.Fatal(err)
				}
				_, err = LoadAcceptedRoot(store, root)
				assertFinding(t, err, "UNSAFE_FILE")
			})
		}
	}
}

func assertFinding(t *testing.T, err error, code string) {
	t.Helper()
	var finding *intake.Finding
	if !errors.As(err, &finding) || finding.Code != code {
		t.Fatalf("wanted %s finding, got %v", code, err)
	}
}
