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
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

type candidateManifest struct {
	SchemaVersion      string              `json:"schema_version"`
	Classification     string              `json:"classification"`
	Files              []candidateFile     `json:"files"`
	HostileExecutables []hostileExecutable `json:"hostile_executables"`
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
	ID                string   `json:"id"`
	Class             string   `json:"class"`
	Source            string   `json:"source"`
	Digest            string   `json:"digest"`
	PromotionReceipt  string   `json:"promotion_receipt"`
	AllowedOperations []string `json:"allowed_operation_ids"`
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
	manifest := candidateManifest{SchemaVersion: policyVersion, Classification: "QUARANTINED", Files: []candidateFile{}, HostileExecutables: []hostileExecutable{}}
	objects := []intake.Object{}
	objectDigests := map[string]bool{}
	collisions := map[string]string{}
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
		if mode&os.ModeSymlink != 0 {
			return &walkFinding{Finding{Code: "UNSAFE_SYMLINK", Disposition: "QUARANTINE", Path: rel, Message: "symbolic links are forbidden"}}
		}
		if mode.IsDir() {
			directories++
			if directories > policy.Quotas.MaxDirectories {
				return &walkFinding{Finding{Code: "QUOTA_EXCEEDED", Disposition: "QUARANTINE", Path: rel, Message: "directory quota exceeded"}}
			}
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
		manifest.Files = append(manifest.Files, candidateFile{Path: rel, CollisionKey: key, ObjectID: objectID, Digest: digest, ByteSize: int64(len(data)), MediaKind: media, Classification: "QUARANTINED", Provenance: "candidate-root:" + intake.DigestBytes([]byte(clean))})
		if !objectDigests[digest] {
			objectDigests[digest] = true
			objects = append(objects, intake.Object{ID: objectID, Digest: digest, Bytes: data})
		}
		if class := classifyExecutable(rel, data, mode); class != "" {
			manifest.HostileExecutables = append(manifest.HostileExecutables, hostileExecutable{ID: "exec." + strings.TrimPrefix(digest, "sha256:")[:16], Class: class, Source: rel, Digest: digest, PromotionReceipt: "", AllowedOperations: []string{}})
		}
		return nil
	})
	if err != nil {
		var wf *walkFinding
		if ok := asWalkFinding(err, &wf); ok {
			return candidateManifest{}, nil, &wf.Finding
		}
		return deny("ROOT_CONFINEMENT_FAILED", "QUARANTINE", rootPath, err.Error())
	}
	if len(manifest.HostileExecutables) > 0 {
		first := manifest.HostileExecutables[0]
		return deny("UNPROMOTED_EXECUTABLE", "QUARANTINE", first.Source, "hostile executable inventory item has no promotion binding")
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
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
	lower := strings.ToLower(name)
	text := strings.ToLower(string(data))
	switch {
	case mode&0o111 != 0:
		return "ARCHIVE_DECLARED_EXECUTABLE"
	case strings.HasSuffix(lower, "build.rs"):
		return "CARGO_BUILD_SCRIPT"
	case lower == "pom.xml" && (strings.Contains(text, "<plugin>") || strings.Contains(text, "annotationprocessorpaths")):
		return "MAVEN_PLUGIN"
	case strings.HasSuffix(lower, "cargo.toml") && strings.Contains(text, "proc-macro = true"):
		return "RUST_PROC_MACRO"
	case strings.Contains(lower, "jdt") || strings.Contains(lower, "rust-analyzer") || strings.Contains(lower, "glancer"):
		return "LANGUAGE_SERVER_PLUGIN"
	case strings.Contains(lower, "autobahn") || strings.Contains(text, "autobahn-testsuite"):
		return "AUTOBAHN_SCRIPT"
	case strings.Contains(lower, "container") && (strings.Contains(text, "entrypoint") || strings.Contains(text, "cmd")):
		return "CONTAINER_ENTRYPOINT"
	}
	return ""
}

var _ = fmt.Sprintf
