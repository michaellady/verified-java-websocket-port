package intake

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var objectIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

type durableManifest struct {
	SchemaVersion string                  `json:"schema_version"`
	RootDigest    string                  `json:"root_digest"`
	Objects       []durableManifestObject `json:"objects"`
}

type durableManifestObject struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
	Path   string `json:"path"`
}

// PromoteDirectory commits an entire verified batch by one same-filesystem
// directory rename. Until that rename, no object is visible under accepted/.
func PromoteDirectory(base string, objects []Object) (string, error) {
	cleanBase := filepath.Clean(base)
	if !filepath.IsAbs(cleanBase) || cleanBase == string(filepath.Separator) || len(objects) == 0 {
		return "", deny("INVALID_PROMOTION_STORE", "$", "protected promotion store must be a specific absolute directory and batch must be nonempty")
	}
	ordered := append([]Object(nil), objects...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	manifest := durableManifest{SchemaVersion: "1.0.0"}
	seenIDs := make(map[string]string)
	var rootInput strings.Builder
	for _, object := range ordered {
		if !objectIDPattern.MatchString(object.ID) || !validateDigest(object.Digest) || DigestBytes(object.Bytes) != object.Digest {
			return "", deny("DIGEST_MISMATCH", "$.objects", "object ID or digest is invalid")
		}
		if prior, exists := seenIDs[object.ID]; exists {
			if prior != object.Digest {
				return "", deny("ARTIFACT_DRIFT", "$.objects", "object ID is bound to conflicting bytes")
			}
			return "", deny("DUPLICATE_ARCHIVE_ENTRY", "$.objects", "duplicate object ID")
		}
		seenIDs[object.ID] = object.Digest
		rootInput.WriteString(object.ID)
		rootInput.WriteByte('=')
		rootInput.WriteString(object.Digest)
		rootInput.WriteByte('\n')
		manifest.Objects = append(manifest.Objects, durableManifestObject{ID: object.ID, Digest: object.Digest, Path: "objects/" + object.Digest[7:]})
	}
	manifest.RootDigest = DigestBytes([]byte(rootInput.String()))
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", deny("PARTIAL_PUBLICATION", "$", err.Error())
	}
	manifestBytes = append(manifestBytes, '\n')

	accepted := filepath.Join(cleanBase, "accepted")
	destination := filepath.Join(accepted, manifest.RootDigest[7:])
	if existing, err := os.ReadFile(filepath.Join(destination, "manifest.json")); err == nil {
		if !bytes.Equal(existing, manifestBytes) {
			return "", deny("ARTIFACT_DRIFT", destination, "existing accepted root has a different manifest")
		}
		if err := verifyDurableObjects(destination, ordered); err != nil {
			return "", err
		}
		return manifest.RootDigest, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", deny("PARTIAL_PUBLICATION", destination, err.Error())
	}
	if err := os.MkdirAll(accepted, 0o700); err != nil {
		return "", deny("PARTIAL_PUBLICATION", accepted, err.Error())
	}
	stage, err := os.MkdirTemp(cleanBase, ".staging-")
	if err != nil {
		return "", deny("PARTIAL_PUBLICATION", cleanBase, err.Error())
	}
	defer os.RemoveAll(stage)
	objectDirectory := filepath.Join(stage, "objects")
	if err := os.Mkdir(objectDirectory, 0o700); err != nil {
		return "", deny("PARTIAL_PUBLICATION", stage, err.Error())
	}
	written := make(map[string]struct{})
	for _, object := range ordered {
		path := filepath.Join(objectDirectory, object.Digest[7:])
		if _, exists := written[path]; exists {
			continue
		}
		written[path] = struct{}{}
		if err := writeExclusiveSynced(path, object.Bytes, 0o400); err != nil {
			return "", deny("PARTIAL_PUBLICATION", path, err.Error())
		}
	}
	if err := writeExclusiveSynced(filepath.Join(stage, "manifest.json"), manifestBytes, 0o400); err != nil {
		return "", deny("PARTIAL_PUBLICATION", stage, err.Error())
	}
	if err := syncDirectory(stage); err != nil {
		return "", deny("PARTIAL_PUBLICATION", stage, err.Error())
	}
	if err := os.Rename(stage, destination); err != nil {
		if existing, readErr := os.ReadFile(filepath.Join(destination, "manifest.json")); readErr == nil && bytes.Equal(existing, manifestBytes) {
			if verifyErr := verifyDurableObjects(destination, ordered); verifyErr == nil {
				return manifest.RootDigest, nil
			}
		}
		return "", deny("PARTIAL_PUBLICATION", destination, err.Error())
	}
	if err := syncDirectory(accepted); err != nil {
		return "", deny("DURABILITY_UNCERTAIN", accepted, "complete batch is visible but directory fsync failed: "+err.Error())
	}
	return manifest.RootDigest, nil
}

func verifyDurableObjects(destination string, objects []Object) error {
	checked := make(map[string]struct{})
	for _, object := range objects {
		path := filepath.Join(destination, "objects", object.Digest[7:])
		if _, exists := checked[path]; exists {
			continue
		}
		checked[path] = struct{}{}
		data, err := os.ReadFile(path)
		if err != nil || DigestBytes(data) != object.Digest || !bytes.Equal(data, object.Bytes) {
			return deny("ARTIFACT_DRIFT", path, "accepted object bytes are absent or corrupt")
		}
	}
	return nil
}

func writeExclusiveSynced(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
