package formalplan

// US-017 concurrency RESULTS binding gate (pre-landing review round 2,
// results.json finding).
//
// assurance/concurrency/results.json says of itself that its "blob ids and
// artifact digests [were] computed from the tree being committed", and its
// `target` block names the exact driver source and exploration harness the
// PASS was measured against. Nothing in the repository read those values, so
// they went stale twice: the 4b93245 revision still carried the 3df6371-era
// blobs (2dab104.../8d51594...) while the committed tree hashed to
// 9288bd3.../76aeb3c.... A digest that names a tree other than the one it
// claims to describe is exactly the decorative-evidence failure this project
// blocks elsewhere, so it is now mechanically detectable: every file-naming
// digest in the artifact is recomputed here from the tree and compared.
//
// Deliberately NOT wired into the backend evaluation stream: this validates
// the results artifact, not the preregistered plan, and the backend's
// committed evaluation document binds plan findings only. The gate is the
// companion test, which `go test ./...` runs.

import (
	"crypto/sha1" //nolint:gosec // git object ids are SHA-1 by definition
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ConcurrencyResultsDocumentPath is the US-017 exploration PASS artifact.
// ConcurrencyResultsDocumentPath is declared in concurrencyresults.go; both validators share it.

// minimizedSeedDir is where the exploration's pinned minimized artifacts
// live; the artifact names them by seed rather than by path.
const minimizedSeedDir = "rust/ws-driver/fuzz-seeds/us017/minimized"

type cbTargetFile struct {
	Path    string `json:"path"`
	GitBlob string `json:"git_blob"`
}

type cbDigestRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type cbMinimizedArtifact struct {
	Seed   string `json:"seed"`
	SHA256 string `json:"sha256"`
}

type cbResults struct {
	Target struct {
		Symbol  string       `json:"symbol"`
		Source  cbTargetFile `json:"source"`
		Harness cbTargetFile `json:"harness"`
	} `json:"target"`
	PreregisteredPlan cbDigestRef `json:"preregistered_plan"`
	DefectsFound      []struct {
		DefectID              string      `json:"defect_id"`
		MinimizedReproduction cbDigestRef `json:"minimized_reproduction"`
	} `json:"defects_found_and_fixed"`
	Retention struct {
		MinimizedArtifacts []cbMinimizedArtifact `json:"minimized_artifacts"`
	} `json:"retention"`
}

// GitBlobID computes the git object id of `content` as a blob, the same way
// `git hash-object` does: SHA-1 over the header "blob <len>\x00" followed by
// the bytes. Recomputed here rather than shelled out so the gate has no
// external process dependency and fails identically everywhere.
func GitBlobID(content []byte) string {
	hash := sha1.New() //nolint:gosec // git object ids are SHA-1 by definition
	fmt.Fprintf(hash, "blob %d\x00", len(content))
	hash.Write(content)
	return hex.EncodeToString(hash.Sum(nil))
}

// fileSHA256 returns the "sha256:"-prefixed digest of a repository file.
func fileSHA256(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ValidateConcurrencyResults recomputes every file-naming digest recorded in
// the US-017 results artifact against the tree at `root` and returns a typed
// blocking finding for each one that names different bytes. An empty result
// means the artifact describes the tree it is committed with.
func ValidateConcurrencyResultsBindings(root string) []ModelFinding {
	resultsPath := filepath.Join(root, filepath.FromSlash(ConcurrencyResultsDocumentPath))
	raw, err := os.ReadFile(resultsPath)
	if err != nil {
		return []ModelFinding{mpFinding("RESULTS_FILE_UNREADABLE", ConcurrencyResultsDocumentPath, err.Error())}
	}
	if len(raw) > mpMaxArtifactBytes {
		return []ModelFinding{mpFinding("RESULTS_FILE_UNREADABLE", ConcurrencyResultsDocumentPath,
			"results artifact exceeds the bounded size")}
	}
	var results cbResults
	if err := json.Unmarshal(raw, &results); err != nil {
		return []ModelFinding{mpFinding("RESULTS_FILE_UNREADABLE", ConcurrencyResultsDocumentPath, err.Error())}
	}

	var findings []ModelFinding
	read := func(field, relative string) ([]byte, bool) {
		if relative == "" {
			findings = append(findings, mpFinding("RESULTS_TARGET_PATH_MISSING",
				ConcurrencyResultsDocumentPath, field+" names no path"))
			return nil, false
		}
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			findings = append(findings, mpFinding("RESULTS_TARGET_PATH_MISSING",
				ConcurrencyResultsDocumentPath,
				fmt.Sprintf("%s names %s, which is not in the tree: %v", field, relative, err)))
			return nil, false
		}
		return content, true
	}
	checkBlob := func(field string, target cbTargetFile) {
		content, ok := read(field, target.Path)
		if !ok {
			return
		}
		actual := GitBlobID(content)
		if target.GitBlob != actual {
			findings = append(findings, mpFinding("RESULTS_TARGET_BLOB_STALE",
				ConcurrencyResultsDocumentPath,
				fmt.Sprintf("%s records git_blob %s for %s, but the committed tree hashes to %s",
					field, target.GitBlob, target.Path, actual)))
		}
	}
	checkSHA := func(field string, ref cbDigestRef) {
		content, ok := read(field, ref.Path)
		if !ok {
			return
		}
		actual := fileSHA256(content)
		if ref.SHA256 != actual {
			findings = append(findings, mpFinding("RESULTS_ARTIFACT_DIGEST_STALE",
				ConcurrencyResultsDocumentPath,
				fmt.Sprintf("%s records %s for %s, but the committed tree hashes to %s",
					field, ref.SHA256, ref.Path, actual)))
		}
	}

	checkBlob("target.source", results.Target.Source)
	checkBlob("target.harness", results.Target.Harness)
	checkSHA("preregistered_plan", results.PreregisteredPlan)
	for index, defect := range results.DefectsFound {
		field := fmt.Sprintf("defects_found_and_fixed[%d] (%s).minimized_reproduction",
			index, defect.DefectID)
		reference := defect.MinimizedReproduction
		if reference.Path == "" && reference.SHA256 == "" {
			// Not every recorded defect minimizes to a pinned schedule (the
			// harness-side and test-side findings have none); an absent
			// binding is legitimate, a HALF binding never is.
			continue
		}
		if reference.Path == "" || reference.SHA256 == "" {
			findings = append(findings, mpFinding("RESULTS_ARTIFACT_BINDING_INCOMPLETE",
				ConcurrencyResultsDocumentPath,
				field+" records only one half of a path/sha256 binding"))
			continue
		}
		checkSHA(field, reference)
	}
	for index, artifact := range results.Retention.MinimizedArtifacts {
		checkSHA(fmt.Sprintf("retention.minimized_artifacts[%d] (%s)", index, artifact.Seed),
			cbDigestRef{
				Path:   minimizedSeedDir + "/" + artifact.Seed + ".seed",
				SHA256: artifact.SHA256,
			})
	}
	return findings
}
