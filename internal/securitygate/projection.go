package securitygate

import (
	"bytes"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
	"github.com/michaellady/verified-java-websocket-port/internal/lab"
)

type projectionManifest struct {
	SchemaVersion  string               `json:"schema_version"`
	SourceRoot     string               `json:"source_root"`
	Directories    []candidateDirectory `json:"directories"`
	Files          []projectionFile     `json:"files"`
	Classification string               `json:"classification"`
}

type projectionFile struct {
	Path           string `json:"path"`
	ObjectID       string `json:"object_id"`
	Digest         string `json:"digest"`
	ByteSize       int64  `json:"byte_size"`
	Classification string `json:"classification"`
	Provenance     string `json:"provenance"`
}

func materializeProjection(storePath, sourceRoot string, accepted *lab.AcceptedRoot, policy releasePolicy, fixture *fixtureCase) (string, *Finding, error) {
	deny := func(code, disposition, path, message string) (string, *Finding, error) {
		return "", &Finding{Code: code, Disposition: disposition, Path: path, Message: message}, nil
	}
	manifestBytes, ok := accepted.Object("candidate-manifest")
	if !ok {
		return deny("PROMOTION_BINDING_MISMATCH", "QUARANTINE", "$.candidate_manifest", "accepted quarantine root has no candidate manifest")
	}
	var candidate candidateManifest
	if err := intake.DecodeStrict(manifestBytes, &candidate); err != nil {
		return deny("PROMOTION_BINDING_MISMATCH", "QUARANTINE", "$.candidate_manifest", "candidate manifest is not strict: "+err.Error())
	}
	if candidate.SchemaVersion != policyVersion || candidate.Classification != "QUARANTINED" {
		return deny("PROMOTION_BINDING_MISMATCH", "QUARANTINE", "$.candidate_manifest", "candidate manifest schema/classification is not closed")
	}
	if len(candidate.HostileExecutables) != 0 {
		return deny("EXECUTABLE_USE_NOT_BOUND", "QUARANTINE", "$.hostile_executables", "projection source contains executable inventory without complete promotion/use bindings")
	}
	if !sort.SliceIsSorted(candidate.Directories, func(i, j int) bool { return candidate.Directories[i].Path < candidate.Directories[j].Path }) || !sort.SliceIsSorted(candidate.Files, func(i, j int) bool { return candidate.Files[i].Path < candidate.Files[j].Path }) {
		return deny("PUBLIC_PROJECTION_DRIFT", "REVOKE", "$.candidate_manifest", "candidate descendants are not in canonical path order")
	}

	objects := map[string]intake.Object{}
	for _, object := range accepted.Objects() {
		if _, duplicate := objects[object.ID]; duplicate {
			return deny("DUPLICATE_ENTRY", "QUARANTINE", "$.objects", "accepted object ID occurs more than once")
		}
		objects[object.ID] = object
	}
	expectedObjects := map[string]bool{"candidate-manifest": true}
	directories := map[string]candidateDirectory{}
	collisions := map[string]string{}
	for _, directory := range candidate.Directories {
		if code, message := validateCandidatePath(directory.Path, pathPolicy{MaxDepth: 128, MaxComponent: 255, MaxPath: 4096}); code != "" {
			return deny("PUBLIC_DESCENDANT_UNCLASSIFIED", "BLOCK", directory.Path, message)
		}
		if directory.CollisionKey != collisionKey(directory.Path) || collisions[directory.CollisionKey] != "" {
			return deny("PUBLIC_PROJECTION_DRIFT", "REVOKE", directory.Path, "directory collision key is missing, duplicate, or incorrect")
		}
		if !stringInSet(directory.Classification, policy.AllowedClassifications) {
			return deny("PUBLIC_DESCENDANT_UNCLASSIFIED", "BLOCK", directory.Path, "directory lacks one closed classification")
		}
		if !validProjectionProvenance(directory.Provenance, "", sourceRoot) {
			return deny("PUBLIC_PROVENANCE_GAP", "BLOCK", directory.Path, "directory provenance is incomplete or outside the tenant")
		}
		parent := filepath.ToSlash(filepath.Dir(directory.Path))
		if parent != "." {
			parentDirectory, exists := directories[parent]
			if !exists {
				return deny("PUBLIC_DESCENDANT_UNCLASSIFIED", "BLOCK", directory.Path, "directory parent is absent or appears after its child")
			}
			if stringInSet(directory.Classification, policy.IncludedClassifications) && !stringInSet(parentDirectory.Classification, policy.IncludedClassifications) {
				return deny("PUBLIC_DESCENDANT_UNCLASSIFIED", "BLOCK", directory.Path, "included directory has no recursively included classified parent")
			}
		}
		collisions[directory.CollisionKey] = directory.Path
		directories[directory.Path] = directory
	}

	projection := projectionManifest{SchemaVersion: policyVersion, SourceRoot: sourceRoot, Directories: []candidateDirectory{}, Files: []projectionFile{}, Classification: "QUARANTINED"}
	promoted := []intake.Object{}
	promotedIDs := map[string]bool{}
	for _, file := range candidate.Files {
		if code, message := validateCandidatePath(file.Path, pathPolicy{MaxDepth: 128, MaxComponent: 255, MaxPath: 4096}); code != "" {
			return deny("PUBLIC_DESCENDANT_UNCLASSIFIED", "BLOCK", file.Path, message)
		}
		if file.CollisionKey != collisionKey(file.Path) || collisions[file.CollisionKey] != "" {
			return deny("PUBLIC_PROJECTION_DRIFT", "REVOKE", file.Path, "file collision key is missing, duplicate, or incorrect")
		}
		collisions[file.CollisionKey] = file.Path
		if !stringInSet(file.Classification, policy.AllowedClassifications) {
			return deny("PUBLIC_DESCENDANT_UNCLASSIFIED", "BLOCK", file.Path, "file lacks one closed classification")
		}
		parent := filepath.ToSlash(filepath.Dir(file.Path))
		if parent != "." {
			directory, exists := directories[parent]
			if !exists || !stringInSet(directory.Classification, policy.IncludedClassifications) && stringInSet(file.Classification, policy.IncludedClassifications) {
				return deny("PUBLIC_DESCENDANT_UNCLASSIFIED", "BLOCK", file.Path, "included file has no recursively included classified parent")
			}
		}
		object, exists := objects[file.ObjectID]
		expectedObjects[file.ObjectID] = true
		if !exists || object.Digest != file.Digest || int64(len(object.Bytes)) != file.ByteSize || intake.DigestBytes(object.Bytes) != file.Digest {
			return deny("PUBLIC_PROJECTION_DRIFT", "REVOKE", file.Path, "manifest and accepted object bytes differ")
		}
		if !validProjectionProvenance(file.Provenance, file.Digest, sourceRoot) {
			return deny("PUBLIC_PROVENANCE_GAP", "BLOCK", file.Path, "file provenance is incomplete, unverified, or outside the tenant")
		}
		if !stringInSet(file.Classification, policy.IncludedClassifications) {
			continue
		}
		if finding := scanProjectionBytes(policy, file.Path, object.Bytes); finding != nil {
			return "", finding, nil
		}
		publicID := "public." + strings.TrimPrefix(file.Digest, "sha256:")
		projection.Files = append(projection.Files, projectionFile{Path: file.Path, ObjectID: publicID, Digest: file.Digest, ByteSize: file.ByteSize, Classification: file.Classification, Provenance: file.Provenance})
		if !promotedIDs[publicID] {
			promotedIDs[publicID] = true
			promoted = append(promoted, intake.Object{ID: publicID, Digest: file.Digest, Bytes: append([]byte(nil), object.Bytes...)})
		}
	}
	for objectID := range objects {
		if !expectedObjects[objectID] {
			return deny("PUBLIC_DESCENDANT_UNCLASSIFIED", "BLOCK", objectID, "accepted root contains an object absent from the recursive candidate manifest")
		}
	}
	for _, directory := range candidate.Directories {
		if stringInSet(directory.Classification, policy.IncludedClassifications) {
			projection.Directories = append(projection.Directories, directory)
		}
	}
	if fixture != nil && fixture.ExpectedCode != "" {
		return deny("INVALID_SECURITY_POLICY", "BLOCK", "security/fixtures/"+fixture.ID, "the exact candidate projection produced no observed component finding for the bad fixture")
	}
	projectionBytes, err := intake.CanonicalJSON(projection)
	if err != nil {
		return "", nil, err
	}
	promoted = append(promoted, intake.Object{ID: "projection-manifest", Digest: intake.DigestBytes(projectionBytes), Bytes: projectionBytes})
	rootDigest, err := intake.PromoteDirectory(storePath, promoted)
	if err != nil {
		return deny("PARTIAL_PROMOTION", "QUARANTINE", "$.projection", err.Error())
	}
	reopened, err := lab.LoadAcceptedRoot(storePath, rootDigest)
	if err != nil {
		return deny("PUBLIC_PROJECTION_DRIFT", "REVOKE", "$.projection", "private projection CAS did not reopen: "+err.Error())
	}
	retainedManifest, ok := reopened.Object("projection-manifest")
	if !ok || !bytes.Equal(retainedManifest, projectionBytes) {
		return deny("PUBLIC_PROJECTION_DRIFT", "REVOKE", "$.projection", "reopened projection manifest differs")
	}
	for _, file := range projection.Files {
		data, exists := reopened.Object(file.ObjectID)
		if !exists || intake.DigestBytes(data) != file.Digest || int64(len(data)) != file.ByteSize {
			return deny("PUBLIC_PROJECTION_DRIFT", "REVOKE", file.Path, "reopened projection bytes differ")
		}
		if finding := scanProjectionBytes(policy, file.Path, data); finding != nil {
			return "", finding, nil
		}
	}
	return rootDigest, nil, nil
}

func validProjectionProvenance(value, digest, sourceRoot string) bool {
	syntheticPrefix := "scope:SYNTHETIC_NON_CLAIM/company:" + requiredCompany + "/project:" + requiredProject
	verifiedPrefix := "scope:VERIFIED_ACCEPTED_ROOT/company:" + requiredCompany + "/project:" + requiredProject
	if digest == "" {
		return value == syntheticPrefix || sourceRoot != "" && value == verifiedPrefix+"/accepted_root:"+sourceRoot
	}
	if value == syntheticPrefix+"/source:"+digest {
		return true
	}
	return sourceRoot != "" && strings.HasPrefix(value, verifiedPrefix+"/accepted_root:"+sourceRoot+"/object:") && strings.HasSuffix(value, "/digest:"+digest)
}

func scanProjectionBytes(policy releasePolicy, path string, data []byte) *Finding {
	matched := ""
	for _, detector := range policy.Detectors {
		if !bytes.Contains(data, []byte(detector.Token)) {
			continue
		}
		if matched != "" && matched != detector.Finding {
			return &Finding{Code: "PROTECTED_PUBLICATION_DISCLOSURE", Disposition: "REVOKE", Path: path, Message: "public bytes matched multiple protected detector classes"}
		}
		matched = detector.Finding
	}
	if matched == "" {
		return nil
	}
	return &Finding{Code: matched, Disposition: "REVOKE", Path: path, Message: fmt.Sprintf("reopened public bytes matched detector %s", matched)}
}
