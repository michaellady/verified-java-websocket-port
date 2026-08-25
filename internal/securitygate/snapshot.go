package securitygate

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
	"github.com/michaellady/verified-java-websocket-port/internal/lab"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

type candidateManifest struct {
	SchemaVersion      string               `json:"schema_version"`
	Classification     string               `json:"classification"`
	Directories        []candidateDirectory `json:"directories"`
	Files              []candidateFile      `json:"files"`
	HostileExecutables []hostileExecutable  `json:"hostile_executables"`
}
type candidateDirectory struct {
	Path           string `json:"path"`
	CollisionKey   string `json:"collision_key"`
	Classification string `json:"classification"`
	Provenance     string `json:"provenance"`
}
type candidateFile struct {
	Path           string `json:"path"`
	CollisionKey   string `json:"collision_key"`
	ObjectID       string `json:"object_id"`
	Digest         string `json:"digest"`
	ByteSize       int64  `json:"byte_size"`
	MediaKind      string `json:"media_kind"`
	Classification string `json:"classification"`
	Provenance     string `json:"provenance"`
}
type hostileExecutable struct {
	ID                 string   `json:"id"`
	Class              string   `json:"class"`
	Source             string   `json:"source_path_or_component"`
	Digest             string   `json:"digest"`
	ByteSize           int64    `json:"byte_size"`
	DiscoveredBy       string   `json:"discovered_by"`
	DeclaredEntrypoint string   `json:"declared_entrypoint"`
	DependencyLockRoot string   `json:"dependency_lock_root"`
	SBOMRef            string   `json:"sbom_ref"`
	VulnerabilityRef   string   `json:"vulnerability_ref"`
	LicenseRef         string   `json:"license_ref"`
	ProvenanceRef      string   `json:"provenance_ref"`
	PromotionReceipt   string   `json:"promotion_receipt_ref"`
	PromotionScope     string   `json:"promotion_scope"`
	ExpiresAt          string   `json:"expires_at"`
	Revoked            bool     `json:"revoked"`
	AllowedOperations  []string `json:"allowed_operation_ids"`
}

// snapshotRevalidationHook is a package-private deterministic race seam used
// only by inert tests. Production leaves it nil.
var snapshotRevalidationHook func()

func snapshotAcceptedRoot(rootDigest string, accepted *lab.AcceptedRoot, policy ingestionPolicy) (candidateManifest, []intake.Object, *Finding) {
	deny := func(code, disposition, path, message string) (candidateManifest, []intake.Object, *Finding) {
		return candidateManifest{}, nil, &Finding{Code: code, Disposition: disposition, Path: path, Message: message}
	}
	if accepted == nil || !isSHA256Digest(rootDigest) {
		return deny("PROMOTION_BINDING_MISMATCH", "QUARANTINE", "$.candidate_root", "verified accepted source root is absent")
	}
	sourceObjects := accepted.Objects()
	if len(sourceObjects) > policy.Quotas.MaxFiles {
		return deny("QUOTA_EXCEEDED", "QUARANTINE", "$.objects", "accepted object count exceeds the ingestion file quota")
	}
	var totalBytes int64
	for _, object := range sourceObjects {
		objectBytes := int64(len(object.Bytes))
		if objectBytes > policy.Quotas.MaxFileBytes || totalBytes > policy.Quotas.MaxTotalBytes-objectBytes {
			return deny("QUOTA_EXCEEDED", "QUARANTINE", object.ID, "accepted object exceeds the ingestion file or total byte quota")
		}
		totalBytes += objectBytes
	}
	manifest := candidateManifest{SchemaVersion: policyVersion, Classification: "QUARANTINED", Directories: []candidateDirectory{}, Files: []candidateFile{}, HostileExecutables: []hostileExecutable{}}
	objects := make([]intake.Object, 0, len(sourceObjects))
	seenDigests := map[string]bool{}
	for _, object := range sourceObjects {
		if code, message := validateCandidatePath(object.ID, policy.Paths); code != "" {
			return deny(code, "QUARANTINE", object.ID, message)
		}
		if intake.DigestBytes(object.Bytes) != object.Digest {
			return deny("PROVENANCE_DIGEST_MISMATCH", "QUARANTINE", object.ID, "accepted object bytes no longer match verified provenance")
		}
		media, archiveFinding := inspectArchive(object.ID, object.Bytes, policy)
		if archiveFinding != nil {
			return candidateManifest{}, nil, archiveFinding
		}
		blobID := "blob." + strings.TrimPrefix(object.Digest, "sha256:")
		manifest.Files = append(manifest.Files, candidateFile{
			Path:           object.ID,
			CollisionKey:   collisionKey(object.ID),
			ObjectID:       blobID,
			Digest:         object.Digest,
			ByteSize:       int64(len(object.Bytes)),
			MediaKind:      media,
			Classification: "QUARANTINED",
			Provenance:     "scope:VERIFIED_ACCEPTED_ROOT/company:" + requiredCompany + "/project:" + requiredProject + "/accepted_root:" + rootDigest + "/object:" + object.ID + "/digest:" + object.Digest,
		})
		if !seenDigests[object.Digest] {
			seenDigests[object.Digest] = true
			objects = append(objects, intake.Object{ID: blobID, Digest: object.Digest, Bytes: append([]byte(nil), object.Bytes...)})
		}
		for _, executable := range discoverExecutables(object.ID, object.Bytes, 0o400, media) {
			manifest.HostileExecutables = append(manifest.HostileExecutables, executable)
		}
	}
	if len(manifest.HostileExecutables) != 0 {
		return deny("UNPROMOTED_EXECUTABLE", "QUARANTINE", manifest.HostileExecutables[0].Source, "hostile executable inventory has no independently verified promotion/use binding")
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	sort.Slice(objects, func(i, j int) bool { return objects[i].ID < objects[j].ID })
	return manifest, objects, nil
}

func snapshotCandidate(rootPath string, policy ingestionPolicy) (candidateManifest, []intake.Object, *Finding) {
	deny := func(code, disposition, path, message string) (candidateManifest, []intake.Object, *Finding) {
		return candidateManifest{}, nil, &Finding{Code: code, Disposition: disposition, Path: path, Message: message}
	}
	clean := filepath.Clean(rootPath)
	if !filepath.IsAbs(clean) || clean == string(filepath.Separator) {
		return deny("ROOT_CONFINEMENT_FAILED", "QUARANTINE", rootPath, "candidate root must be a specific absolute directory")
	}
	root, err := os.OpenRoot(clean)
	if err != nil {
		return deny("ROOT_CONFINEMENT_FAILED", "QUARANTINE", rootPath, err.Error())
	}
	defer root.Close()
	rootInfo, err := root.Lstat(".")
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return deny("ROOT_CONFINEMENT_FAILED", "QUARANTINE", rootPath, "candidate root is not a real directory")
	}
	rootDevice, ok := deviceAndLinks(rootInfo)
	if !ok {
		return deny("ROOT_CONFINEMENT_FAILED", "QUARANTINE", rootPath, "filesystem identity is unavailable")
	}
	manifest := candidateManifest{SchemaVersion: policyVersion, Classification: "QUARANTINED", Directories: []candidateDirectory{}, Files: []candidateFile{}, HostileExecutables: []hostileExecutable{}}
	objects := []intake.Object{}
	objectDigests := map[string]bool{}
	collisions := map[string]string{}
	entrySet := map[string]os.FileInfo{".": rootInfo}
	var files, directories int
	var total int64
	err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == "." {
			return nil
		}
		rel := filepath.ToSlash(name)
		if code, message := validateCandidatePath(rel, policy.Paths); code != "" {
			return &walkFinding{Finding{Code: code, Disposition: "QUARANTINE", Path: rel, Message: message}}
		}
		key := collisionKey(rel)
		if prior, exists := collisions[key]; exists && prior != rel {
			return &walkFinding{Finding{Code: "NORMALIZATION_COLLISION", Disposition: "QUARANTINE", Path: rel, Message: "path collides with " + prior}}
		}
		collisions[key] = rel
		info, err := root.Lstat(rel)
		if err != nil {
			return err
		}
		devLinks, supported := deviceAndLinks(info)
		if !supported || devLinks.device != rootDevice.device {
			return &walkFinding{Finding{Code: "ROOT_CONFINEMENT_FAILED", Disposition: "QUARANTINE", Path: rel, Message: "entry crossed the root device"}}
		}
		mode := info.Mode()
		entrySet[rel] = info
		if mode&os.ModeSymlink != 0 {
			return &walkFinding{Finding{Code: "UNSAFE_SYMLINK", Disposition: "QUARANTINE", Path: rel, Message: "symbolic links are forbidden"}}
		}
		if mode.IsDir() {
			directories++
			if directories > policy.Quotas.MaxDirectories {
				return &walkFinding{Finding{Code: "QUOTA_EXCEEDED", Disposition: "QUARANTINE", Path: rel, Message: "directory quota exceeded"}}
			}
			manifest.Directories = append(manifest.Directories, candidateDirectory{
				Path: rel, CollisionKey: key, Classification: "QUARANTINED",
				Provenance: "scope:SYNTHETIC_NON_CLAIM/company:" + requiredCompany + "/project:" + requiredProject,
			})
			return nil
		}
		if !mode.IsRegular() {
			return &walkFinding{Finding{Code: "SPECIAL_FILE_DENIED", Disposition: "QUARANTINE", Path: rel, Message: "special files are forbidden"}}
		}
		if devLinks.links != 1 {
			return &walkFinding{Finding{Code: "HARD_LINK_DENIED", Disposition: "QUARANTINE", Path: rel, Message: "regular file link count is not one"}}
		}
		files++
		if files > policy.Quotas.MaxFiles || info.Size() < 0 || info.Size() > policy.Quotas.MaxFileBytes || total > policy.Quotas.MaxTotalBytes-info.Size() {
			return &walkFinding{Finding{Code: "QUOTA_EXCEEDED", Disposition: "QUARANTINE", Path: rel, Message: "file or byte quota exceeded"}}
		}
		file, err := root.Open(rel)
		if err != nil {
			return err
		}
		opened, err := file.Stat()
		if err != nil || !sameMetadata(info, opened) {
			file.Close()
			return &walkFinding{Finding{Code: "IMMUTABLE_SNAPSHOT_FAILED", Disposition: "QUARANTINE", Path: rel, Message: "identity changed before read"}}
		}
		data, err := io.ReadAll(io.LimitReader(file, policy.Quotas.MaxFileBytes+1))
		after, statErr := file.Stat()
		closeErr := file.Close()
		final, lstatErr := root.Lstat(rel)
		if err != nil || statErr != nil || closeErr != nil || lstatErr != nil || !sameMetadata(info, after) || !sameMetadata(info, final) || int64(len(data)) != info.Size() {
			return &walkFinding{Finding{Code: "IMMUTABLE_SNAPSHOT_FAILED", Disposition: "QUARANTINE", Path: rel, Message: "identity changed during one read"}}
		}
		total += int64(len(data))
		digest := intake.DigestBytes(data)
		objectID := "blob." + strings.TrimPrefix(digest, "sha256:")
		media, archiveFinding := inspectArchive(rel, data, policy)
		if archiveFinding != nil {
			return &walkFinding{*archiveFinding}
		}
		provenance := "scope:SYNTHETIC_NON_CLAIM/company:" + requiredCompany + "/project:" + requiredProject + "/source:" + digest
		manifest.Files = append(manifest.Files, candidateFile{Path: rel, CollisionKey: key, ObjectID: objectID, Digest: digest, ByteSize: int64(len(data)), MediaKind: media, Classification: "QUARANTINED", Provenance: provenance})
		if !objectDigests[digest] {
			objectDigests[digest] = true
			objects = append(objects, intake.Object{ID: objectID, Digest: digest, Bytes: data})
		}
		manifest.HostileExecutables = append(manifest.HostileExecutables, discoverExecutables(rel, data, mode, media)...)
		return nil
	})
	if err != nil {
		var wf *walkFinding
		if ok := asWalkFinding(err, &wf); ok {
			return candidateManifest{}, nil, &wf.Finding
		}
		return deny("ROOT_CONFINEMENT_FAILED", "QUARANTINE", rootPath, err.Error())
	}
	if snapshotRevalidationHook != nil {
		snapshotRevalidationHook()
	}
	seen := map[string]bool{}
	err = fs.WalkDir(root.FS(), ".", func(name string, _ fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel := filepath.ToSlash(name)
		before, ok := entrySet[rel]
		if !ok {
			return &walkFinding{Finding{Code: "IMMUTABLE_SNAPSHOT_FAILED", Disposition: "QUARANTINE", Path: rel, Message: "directory set gained an entry after the one-read snapshot"}}
		}
		after, statErr := root.Lstat(rel)
		if statErr != nil || !sameMetadata(before, after) {
			return &walkFinding{Finding{Code: "IMMUTABLE_SNAPSHOT_FAILED", Disposition: "QUARANTINE", Path: rel, Message: "directory-set identity changed after the one-read snapshot"}}
		}
		seen[rel] = true
		return nil
	})
	if err != nil {
		var wf *walkFinding
		if asWalkFinding(err, &wf) {
			return candidateManifest{}, nil, &wf.Finding
		}
		return deny("IMMUTABLE_SNAPSHOT_FAILED", "QUARANTINE", rootPath, err.Error())
	}
	if len(seen) != len(entrySet) {
		return deny("IMMUTABLE_SNAPSHOT_FAILED", "QUARANTINE", rootPath, "directory set lost an entry after the one-read snapshot")
	}
	if len(manifest.HostileExecutables) > 0 {
		first := manifest.HostileExecutables[0]
		return deny("UNPROMOTED_EXECUTABLE", "QUARANTINE", first.Source, "hostile executable inventory item has no promotion binding")
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	sort.Slice(manifest.Directories, func(i, j int) bool { return manifest.Directories[i].Path < manifest.Directories[j].Path })
	sort.Slice(objects, func(i, j int) bool { return objects[i].ID < objects[j].ID })
	return manifest, objects, nil
}

type deviceLinks struct {
	device uint64
	links  uint64
}

func deviceAndLinks(info os.FileInfo) (deviceLinks, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return deviceLinks{}, false
	}
	return deviceLinks{device: uint64(stat.Dev), links: uint64(stat.Nlink)}, true
}
func sameMetadata(a, b os.FileInfo) bool {
	if a == nil || b == nil || !os.SameFile(a, b) || a.Mode() != b.Mode() || a.Size() != b.Size() || !a.ModTime().Equal(b.ModTime()) {
		return false
	}
	left, lok := deviceAndLinks(a)
	right, rok := deviceAndLinks(b)
	return lok && rok && left == right && changeTime(a) == changeTime(b)
}
func changeTime(info os.FileInfo) string {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	value := reflect.ValueOf(stat).Elem()
	for _, name := range []string{"Ctimespec", "Ctim", "Ctime"} {
		field := value.FieldByName(name)
		if field.IsValid() {
			return fmt.Sprint(field.Interface())
		}
	}
	return ""
}

type walkFinding struct{ Finding }

func (w *walkFinding) Error() string { return w.Code + " at " + w.Path + ": " + w.Message }
func asWalkFinding(err error, target **walkFinding) bool {
	value, ok := err.(*walkFinding)
	if ok {
		*target = value
	}
	return ok
}

func validateCandidatePath(name string, policy pathPolicy) (string, string) {
	if name == "" || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "\\") || (len(name) >= 2 && name[1] == ':') {
		return "ABSOLUTE_PATH", "absolute path is forbidden"
	}
	if strings.Contains(name, "\\") || strings.ContainsRune(name, 0) {
		return "PATH_TRAVERSAL", "backslash and NUL paths are forbidden"
	}
	if !utf8.ValidString(name) {
		return "NONCANONICAL_PATH", "path is not UTF-8"
	}
	if norm.NFC.String(name) != name {
		return "NONCANONICAL_PATH", "path is not NFC"
	}
	if len(name) > policy.MaxPath {
		return "PATH_TRAVERSAL", "path length exceeds policy"
	}
	parts := strings.Split(name, "/")
	if len(parts) > policy.MaxDepth {
		return "PATH_TRAVERSAL", "path depth exceeds policy"
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "PATH_TRAVERSAL", "empty, dot, and parent components are forbidden"
		}
		if len(part) > policy.MaxComponent {
			return "PATH_TRAVERSAL", "component length exceeds policy"
		}
	}
	return "", ""
}
func collisionKey(name string) string {
	parts := strings.Split(name, "/")
	for i := range parts {
		parts[i] = norm.NFC.String(cases.Fold().String(parts[i]))
	}
	return strings.Join(parts, "/")
}

func inspectArchive(name string, data []byte, policy ingestionPolicy) (string, *Finding) {
	archivePolicy := intake.ArchivePolicy{DeclaredExecutables: map[string]bool{}, DeclaredNested: map[string]string{}, MaxEntries: policy.Quotas.MaxArchiveEntries, MaxFileBytes: policy.Quotas.MaxFileBytes, MaxTotalBytes: policy.Quotas.MaxExpandedBytes, MaxDepth: policy.Quotas.MaxArchiveDepth}
	lower := strings.ToLower(name)
	if bytes.HasPrefix(data, []byte{'P', 'K', 3, 4}) || strings.HasSuffix(lower, ".zip") || strings.HasSuffix(lower, ".jar") || strings.HasSuffix(lower, ".vsix") {
		_, err := intake.InspectZip(bytes.NewReader(data), int64(len(data)), archivePolicy)
		if err != nil {
			return "ZIP", translateIntakeFinding(err, name)
		}
		return "ZIP", nil
	}
	if len(data) >= 265 && string(data[257:262]) == "ustar" || strings.HasSuffix(lower, ".tar") {
		_, err := intake.InspectTar(bytes.NewReader(data), archivePolicy)
		if err != nil {
			return "TAR", translateIntakeFinding(err, name)
		}
		return "TAR", nil
	}
	return "REGULAR", nil
}
func translateIntakeFinding(err error, path string) *Finding {
	if value, ok := err.(*intake.Finding); ok {
		code := value.Code
		switch code {
		case "UNSAFE_ARCHIVE_ENTRY":
			code = "SPECIAL_FILE_DENIED"
		case "DUPLICATE_ARCHIVE_ENTRY":
			code = "DUPLICATE_ENTRY"
		case "INVALID_PATH_ENCODING":
			code = "NONCANONICAL_PATH"
		}
		return &Finding{Code: code, Disposition: "QUARANTINE", Path: path + ":" + value.Path, Message: value.Message}
	}
	return &Finding{Code: "ARCHIVE_LIMIT_EXCEEDED", Disposition: "QUARANTINE", Path: path, Message: err.Error()}
}
func classifyExecutable(name string, data []byte, mode os.FileMode) string {
	items := discoverExecutables(name, data, mode, "REGULAR")
	if len(items) != 0 {
		return items[0].Class
	}
	return ""
}

func discoverExecutables(name string, data []byte, mode os.FileMode, media string) []hostileExecutable {
	lower := strings.ToLower(filepath.ToSlash(name))
	base := filepath.Base(lower)
	text := strings.ToLower(string(data))
	classes := []string{}
	add := func(class string, when bool) {
		if !when {
			return
		}
		for _, existing := range classes {
			if existing == class {
				return
			}
		}
		classes = append(classes, class)
	}

	isPOM := base == "pom.xml"
	add("MAVEN_CORE", isPOM)
	add("MAVEN_PLUGIN", isPOM && containsAny(text, "<plugin>", "<plugins>", "<pluginmanagement>", "<reporting>", "<extensions>true</extensions>", "<goal>", "<phase>"))
	add("MAVEN_EXTENSION", lower == ".mvn/extensions.xml" || strings.HasSuffix(lower, "/.mvn/extensions.xml") || isPOM && strings.Contains(text, "<extensions>true</extensions>"))
	add("MAVEN_ANNOTATION_PROCESSOR", isPOM && containsAny(text, "annotationprocessorpaths", "annotationprocessors", "-processor", "maven-processor-plugin"))
	add("JVM_DEPENDENCY", isPOM && containsAny(text, "<dependency", "<dependencies", "<parent", "<dependencymanagement", "<scope>import</scope>"))

	add("RUST_TOOLCHAIN", base == "rust-toolchain" || base == "rust-toolchain.toml")
	add("CARGO_BUILD_SCRIPT", base == "build.rs" || strings.HasSuffix(lower, "/build.rs") || strings.HasSuffix(lower, "cargo.toml") && containsAny(text, "build =", "build="))
	add("RUST_PROC_MACRO", strings.HasSuffix(lower, "cargo.toml") && containsAny(text, "proc-macro = true", "proc-macro=true"))
	isCargoConfig := lower == ".cargo/config" || lower == ".cargo/config.toml" || strings.HasSuffix(lower, "/.cargo/config") || strings.HasSuffix(lower, "/.cargo/config.toml")
	add("CARGO_RUNNER_OR_WRAPPER", isCargoConfig && containsAny(text, "runner", "rustc-wrapper", "rustdoc-wrapper", "linker"))
	add("RUST_DEPENDENCY", strings.HasSuffix(lower, "cargo.lock") && strings.Contains(text, "[[package]]") || strings.HasSuffix(lower, "cargo.toml") && containsAny(text, "[dependencies]", "[build-dependencies]", "[dev-dependencies]", "target.'"))

	add("JDT_LS_IMPORT", containsAny(lower, "jdt.ls", "jdt-ls", "jdtls", "jdt-") || containsAny(text, "jdt.ls", "jdt-ls", "jdtls"))
	add("RUST_ANALYZER_IMPORT", strings.Contains(lower, "rust-analyzer") || strings.Contains(text, "rust-analyzer"))
	add("GLANCER_IMPORT", strings.Contains(lower, "glancer") || strings.Contains(text, "glancer"))
	add("LANGUAGE_SERVER_PLUGIN", containsAny(lower, "language-server", "lsp", "plugins.json", "extensions.json") || containsAny(text, "language server", "language-server", "workspace/didchangeconfiguration", "build server"))

	isAutobahn := strings.Contains(lower, "autobahn") || containsAny(text, "autobahn-testsuite", "wstest", "fuzzingclient", "fuzzingserver")
	add("AUTOBAHN_PYTHON_RUNTIME", isAutobahn && containsAny(lower, "python", "runtime") || containsAny(text, "python3", "python_version"))
	add("AUTOBAHN_PYTHON_DISTRIBUTION", isAutobahn && containsAny(lower, "dist-info", "site-packages", "requirements", "wheel") || containsAny(text, "autobahn-testsuite==", "crossbar=="))
	add("AUTOBAHN_SCRIPT", isAutobahn)

	isContainer := containsAny(lower, "container", "oci", "manifest.json", "config.json", "dockerfile") || containsAny(text, "oci.image", "rootfs", "architecture")
	add("CONTAINER_ENTRYPOINT", isContainer && containsAny(text, "entrypoint", "\"process\":{", "\"args\":"))
	add("CONTAINER_COMMAND", isContainer && containsAny(text, "\"cmd\"", "\"command\""))
	add("CONTAINER_LAYER", isContainer && containsAny(text, "oci.image.layer", "container.layer", "\"layers\"", "rootfs.diff_ids"))
	add("CONTAINER_RUNTIME_HELPER", isContainer && containsAny(text, "runc", "containerd", "docker-init", "runtime helper"))

	add("ARCHIVE_DECODER", media == "ZIP" || media == "TAR")
	add("ARCHIVE_DECLARED_EXECUTABLE", mode&0o111 != 0)
	add("SECURITYCTL", base == "securityctl" || base == "securityctl.exe")
	add("SANDBOX_SUPERVISOR", containsAny(base, "sandbox-supervisor", "security-supervisor"))

	sort.Strings(classes)
	digest := intake.DigestBytes(data)
	items := make([]hostileExecutable, 0, len(classes))
	for _, class := range classes {
		identity := intake.DigestBytes([]byte(class + "\x00" + name + "\x00" + digest))
		items = append(items, hostileExecutable{
			ID:                "exec." + strings.TrimPrefix(identity, "sha256:")[:24],
			Class:             class,
			Source:            filepath.ToSlash(name),
			Digest:            digest,
			ByteSize:          int64(len(data)),
			DiscoveredBy:      "STATIC_RETAINED_SNAPSHOT_V1",
			AllowedOperations: []string{},
		})
	}
	return items
}

func containsAny(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if strings.Contains(value, candidate) {
			return true
		}
	}
	return false
}
