package lab

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

type AcceptedManifest struct {
	SchemaVersion string                   `json:"schema_version"`
	RootDigest    string                   `json:"root_digest"`
	Objects       []AcceptedManifestObject `json:"objects"`
}

type AcceptedManifestObject struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
	Path   string `json:"path"`
}

// AcceptedRoot is a byte-verified in-memory snapshot. No later operation
// re-reads candidate-controlled source paths.
type AcceptedRoot struct {
	manifest AcceptedManifest
	objects  []intake.Object
}

func (r *AcceptedRoot) Manifest() AcceptedManifest {
	copy := r.manifest
	copy.Objects = append([]AcceptedManifestObject(nil), r.manifest.Objects...)
	return copy
}

func (r *AcceptedRoot) Objects() []intake.Object {
	objects := make([]intake.Object, len(r.objects))
	for index, object := range r.objects {
		objects[index] = intake.Object{ID: object.ID, Digest: object.Digest, Bytes: append([]byte(nil), object.Bytes...)}
	}
	return objects
}

func (r *AcceptedRoot) Object(id string) ([]byte, bool) {
	index := sort.Search(len(r.objects), func(index int) bool { return r.objects[index].ID >= id })
	if index == len(r.objects) || r.objects[index].ID != id {
		return nil, false
	}
	return append([]byte(nil), r.objects[index].Bytes...), true
}

// LoadAcceptedRoot reads only the fixed manifest and digest-addressed object
// members beneath storeBase/accepted/root. Manifest paths cannot redirect it.
func LoadAcceptedRoot(storeBase, rootDigest string) (*AcceptedRoot, error) {
	base, err := cleanAbsoluteDirectory(storeBase, "$.store_base")
	if err != nil {
		return nil, err
	}
	if !isDigest(rootDigest) {
		return nil, finding("INVALID_DIGEST", "$.root_digest", "accepted root must be a lowercase SHA-256 digest")
	}
	rootPath := filepath.Join(base, "accepted", rootDigest[7:])
	for _, directory := range []string{base, filepath.Join(base, "accepted"), rootPath, filepath.Join(rootPath, "objects")} {
		if err := requireRealDirectory(directory); err != nil {
			return nil, err
		}
	}
	manifestBytes, err := readBoundedRegular(filepath.Join(rootPath, "manifest.json"), maxManifestBytes)
	if err != nil {
		return nil, err
	}
	var manifest AcceptedManifest
	if err := intake.DecodeStrict(manifestBytes, &manifest); err != nil {
		return nil, err
	}
	if manifest.SchemaVersion != "1.0.0" || manifest.RootDigest != rootDigest || len(manifest.Objects) == 0 || len(manifest.Objects) > 4096 {
		return nil, finding("INVALID_ACCEPTED_MANIFEST", "$.manifest", "schema, root, or object count is invalid")
	}
	if !sort.SliceIsSorted(manifest.Objects, func(i, j int) bool { return manifest.Objects[i].ID < manifest.Objects[j].ID }) {
		return nil, finding("NONCANONICAL_MANIFEST", "$.objects", "objects must be strictly ID-sorted")
	}
	objects := make([]intake.Object, 0, len(manifest.Objects))
	seenIDs := make(map[string]struct{}, len(manifest.Objects))
	var rootInput strings.Builder
	var totalBytes int64
	for index, member := range manifest.Objects {
		path := fmt.Sprintf("$.objects[%d]", index)
		if !idPattern.MatchString(member.ID) || !isDigest(member.Digest) || member.Path != "objects/"+member.Digest[7:] {
			return nil, finding("INVALID_ACCEPTED_MANIFEST", path, "object ID, digest, or fixed digest path is invalid")
		}
		if _, duplicate := seenIDs[member.ID]; duplicate {
			return nil, finding("DUPLICATE_ENTRY", path+".id", "object ID occurs more than once")
		}
		seenIDs[member.ID] = struct{}{}
		rootInput.WriteString(member.ID)
		rootInput.WriteByte('=')
		rootInput.WriteString(member.Digest)
		rootInput.WriteByte('\n')
		remaining := int64(maxAcceptedBytes) - totalBytes
		maximum := int64(maxObjectBytes)
		if remaining < maximum {
			maximum = remaining
		}
		if maximum <= 0 {
			return nil, finding("INPUT_TOO_LARGE", "$.objects", "accepted root exceeds the total byte bound")
		}
		data, err := readBoundedRegular(filepath.Join(rootPath, "objects", member.Digest[7:]), maximum)
		if err != nil {
			return nil, err
		}
		if intake.DigestBytes(data) != member.Digest {
			return nil, finding("DIGEST_MISMATCH", path, "accepted object bytes do not match their manifest digest")
		}
		totalBytes += int64(len(data))
		objects = append(objects, intake.Object{ID: member.ID, Digest: member.Digest, Bytes: data})
	}
	if intake.DigestBytes([]byte(rootInput.String())) != rootDigest {
		return nil, finding("DIGEST_MISMATCH", "$.root_digest", "manifest members do not derive the declared accepted root")
	}
	return &AcceptedRoot{manifest: manifest, objects: objects}, nil
}

// Materialize writes the verified snapshot through intake's durable batch
// primitive. Reordering is harmless because that primitive canonicalizes IDs.
func (r *AcceptedRoot) Materialize(destinationBase string) (string, error) {
	if r == nil || len(r.objects) == 0 {
		return "", finding("INVALID_ACCEPTED_ROOT", "$", "verified root is absent")
	}
	destination, err := cleanAbsoluteDirectory(destinationBase, "$.destination_base")
	if err != nil {
		return "", err
	}
	if info, statErr := os.Lstat(destination); errors.Is(statErr, os.ErrNotExist) {
		if err := os.Mkdir(destination, 0o700); err != nil {
			return "", finding("PARTIAL_PUBLICATION", destination, err.Error())
		}
		if err := syncDir(filepath.Dir(destination)); err != nil {
			return "", finding("DURABILITY_UNCERTAIN", destination, err.Error())
		}
	} else if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", finding("UNSAFE_DIRECTORY", destination, "materialization base must be a real directory")
	}
	accepted := filepath.Join(destination, "accepted")
	if _, statErr := os.Lstat(accepted); statErr == nil {
		if err := requireRealDirectory(accepted); err != nil {
			return "", err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", finding("UNSAFE_DIRECTORY", accepted, statErr.Error())
	}
	root, err := intake.PromoteDirectory(destination, r.Objects())
	if err != nil {
		return "", err
	}
	if root != r.manifest.RootDigest {
		return "", finding("DIGEST_MISMATCH", "$.destination_base", "materialized root differs from verified source root")
	}
	verified, err := LoadAcceptedRoot(destination, root)
	if err != nil {
		return "", err
	}
	left, err := intake.CanonicalJSON(r.manifest)
	if err != nil {
		return "", err
	}
	right, err := intake.CanonicalJSON(verified.manifest)
	if err != nil {
		return "", err
	}
	if string(left) != string(right) {
		return "", finding("ARTIFACT_DRIFT", "$.destination_base", "materialized manifest differs from the verified source snapshot")
	}
	return root, nil
}
