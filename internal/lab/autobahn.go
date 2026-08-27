package lab

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

var autobahnCasePattern = regexp.MustCompile(`^([1-7]|9|10|12|13)\.[0-9]+(?:\.[0-9]+)*$`)
var autobahnPythonTokenPattern = regexp.MustCompile(`\bCase([0-9]+(?:_[0-9X]+)+)\b`)

var selectedAutobahnFamilies = []string{"1.*", "2.*", "3.*", "4.*", "5.*", "6.*", "7.*", "10.*"}
var excludedAutobahnFamilies = []string{"9.*", "12.*", "13.*"}

const (
	PinnedAutobahnSourceArchiveDigest = "sha256:c17e0e22b9ca0f6ebd415bb14dc60e7fd7ea57b50fbc4ba12892dd454b98e66b"
	PinnedAutobahnRegistryDigest      = "sha256:12ce097739b14751daefa1fd1ee4125ca1b95584759100563c00cf796eac7cb4"
	PinnedAutobahnReportSourceDigest  = "sha256:3bbb21786744023f1c215763a0aa66ab5db543e1826a1ae22b52d7f2876d8d1a"
	pinnedAutobahnArchiveRoot         = "autobahn-testsuite-6ed6f439dc7ed0d7432fe2cf7481b110905ecc5c"
	pinnedAutobahnCaseDirectory       = pinnedAutobahnArchiveRoot + "/autobahntestsuite/autobahntestsuite/case"
	pinnedAutobahnReportSourcePath    = pinnedAutobahnArchiveRoot + "/autobahntestsuite/autobahntestsuite/fuzzing.py"
)

var pinnedAutobahnGeneratorMembers = map[string]struct {
	path   string
	digest string
}{
	"Case6_X_X":  {pinnedAutobahnCaseDirectory + "/case6_x_x.py", "sha256:1497d61710553fbfb76b0085029a267cca2640d9c17ce60e529323eb6577dbeb"},
	"Case7_7_X":  {pinnedAutobahnCaseDirectory + "/case7_7_X.py", "sha256:6084d9b94770982fbd20e60bb47734151d0a655691d773278176f15f67221899"},
	"Case7_9_X":  {pinnedAutobahnCaseDirectory + "/case7_9_X.py", "sha256:842e8a4ff30acc3ba28875ece52e94f58c53ca2b00ec4c4043c53e06207f0def"},
	"Case9_7_X":  {pinnedAutobahnCaseDirectory + "/case9_7_X.py", "sha256:196923c9c2e6116089a3b9b2375eb82c1d8ad0431e98d1570da96d65545c85e6"},
	"Case9_8_X":  {pinnedAutobahnCaseDirectory + "/case9_7_X.py", "sha256:196923c9c2e6116089a3b9b2375eb82c1d8ad0431e98d1570da96d65545c85e6"},
	"Case12_X_X": {pinnedAutobahnCaseDirectory + "/case12_x_x.py", "sha256:c4a07603978c99fd4eb4d3990feed74266bfd40ffa5f65c8990fca6120564a04"},
	"Case13_X_X": {pinnedAutobahnCaseDirectory + "/case12_x_x.py", "sha256:c4a07603978c99fd4eb4d3990feed74266bfd40ffa5f65c8990fca6120564a04"},
}

// VerifyRustAutobahnArchitectureFiles keeps the inert US-019 preparation seam
// disconnected from the incumbent live controller. It is deliberately a
// narrow source/linkage canary over the exact reviewed files, not a claim that
// arbitrary obfuscation is impossible.
func VerifyRustAutobahnArchitectureFiles(repositoryRoot string) error {
	root, err := realRepositoryRoot(repositoryRoot)
	if err != nil {
		return err
	}
	read := func(relative string) ([]byte, error) {
		return readBoundedRegular(filepath.Join(root, filepath.FromSlash(relative)), 4<<20)
	}
	inert, err := read("internal/lab/autobahn_rust.go")
	if err != nil {
		return err
	}
	for _, fragment := range []string{
		"Run" + "AutobahnQualification",
		"new" + "DockerController",
		"run" + "AutobahnClientMode",
		"run" + "AutobahnServerMode",
		"wst" + "est",
		"docker " + "run",
		"exec.Command(" + "\"sh\"",
		"exec.Command(" + "\"bash\"",
	} {
		if bytes.Contains(inert, []byte(fragment)) {
			return finding("AUTOBAHN_STATIC_LIVE_LINKAGE", "internal/lab/autobahn_rust.go", "inert preparation names a live controller, suite runner, Docker, or shell surface")
		}
	}
	cli, err := read("cmd/autobahnctl/main.go")
	if err != nil {
		return err
	}
	prepareBody := goFunctionBody(cli, "func prepareRust(")
	if len(prepareBody) == 0 {
		return finding("AUTOBAHN_TESTEE_LINKAGE_MISSING", "cmd/autobahnctl/main.go", "prepare-rust CLI route is missing")
	}
	for _, fragment := range []string{"Run" + "AutobahnQualification", "Docker", "wst" + "est", "relay", "runner", "jdk", "4*time.Hour"} {
		if bytes.Contains(prepareBody, []byte(fragment)) {
			return finding("AUTOBAHN_STATIC_LIVE_LINKAGE", "cmd/autobahnctl/main.go", "prepare-rust body names a live-only surface")
		}
	}
	mainSource, err := read("rust/websocket-testee/src/main.rs")
	if err != nil {
		return err
	}
	for _, required := range []string{`Some("harness-contract")`, RustAutobahnStatus, "roles=client,server", "network_routes=client,server", "application_echo=false", "multi_case=false", "conformance=false", `Some("client")`, `Some("server")`} {
		if !bytes.Contains(mainSource, []byte(required)) {
			return finding("AUTOBAHN_TESTEE_LINKAGE_MISSING", "rust/websocket-testee/src/main.rs", "Rust process router lacks exact inert/client/server linkage")
		}
	}
	contractBody := rustFunctionBody(mainSource, "fn harness_contract(")
	if len(contractBody) == 0 {
		return finding("AUTOBAHN_TESTEE_LINKAGE_MISSING", "rust/websocket-testee/src/main.rs", "harness-contract function is missing")
	}
	for _, forbidden := range []string{"Tcp", "connect(", "bind(", "client(", "server(", "run_client_once", "run_server_once", "std::env", "Command", "conformance=true", "application_echo=true", "multi_case=true"} {
		if bytes.Contains(contractBody, []byte(forbidden)) {
			return finding("AUTOBAHN_STATIC_LIVE_LINKAGE", "rust/websocket-testee/src/main.rs", "harness-contract route contains network, environment, process, or conformance authority")
		}
	}
	if err := VerifyRustAutobahnStaticFiles(root); err != nil {
		return err
	}
	return nil
}

func goFunctionBody(source []byte, marker string) []byte {
	start := bytes.Index(source, []byte(marker))
	if start < 0 {
		return nil
	}
	rest := source[start+len(marker):]
	end := bytes.Index(rest, []byte("\nfunc "))
	if end < 0 {
		return rest
	}
	return rest[:end]
}

func rustFunctionBody(source []byte, marker string) []byte {
	start := bytes.Index(source, []byte(marker))
	if start < 0 {
		return nil
	}
	rest := source[start+len(marker):]
	end := bytes.Index(rest, []byte("\nfn "))
	if end < 0 {
		return rest
	}
	return rest[:end]
}

func AutobahnFamilies() (selected, excluded []string) {
	return append([]string(nil), selectedAutobahnFamilies...), append([]string(nil), excludedAutobahnFamilies...)
}

type AutobahnRegistry struct {
	SchemaVersion        string   `json:"schema_version"`
	SourceDigest         string   `json:"source_digest"`
	CaseIDs              []string `json:"case_ids"`
	UnresolvedGenerators []string `json:"unresolved_generators"`
	sourceValidated      bool
	caseIDsDigest        string
}

type RegistryExpansion struct {
	ArchiveDigest   string   `json:"archive_digest"`
	MemberPath      string   `json:"member_path"`
	SourceDigest    string   `json:"source_digest"`
	CaseIDs         []string `json:"case_ids"`
	sourceValidated bool
	caseIDsDigest   string
}

// ParsePinnedAutobahnArchive treats the accepted source tarball exclusively as
// data. It validates archive structure and the exact generator subtree before
// deriving fully numeric identities with a deliberately narrow parser for the
// pinned generator forms. Python is never imported or executed.
func ParsePinnedAutobahnArchive(compressed []byte, archiveDigest string) (map[string]RegistryExpansion, error) {
	members, err := readPinnedAutobahnArchive(compressed, archiveDigest)
	if err != nil {
		return nil, err
	}
	return derivePinnedAutobahnExpansions(archiveDigest, members)
}

// ParsePinnedAutobahnRegistryArchive is the closed provenance path: registry
// bytes and generated families are both read from the same verified archive.
func ParsePinnedAutobahnRegistryArchive(compressed []byte, archiveDigest string) (AutobahnRegistry, error) {
	members, err := readPinnedAutobahnArchive(compressed, archiveDigest)
	if err != nil {
		return AutobahnRegistry{}, err
	}
	expansions, err := derivePinnedAutobahnExpansions(archiveDigest, members)
	if err != nil {
		return AutobahnRegistry{}, err
	}
	registryPath := pinnedAutobahnCaseDirectory + "/__init__.py"
	return ParsePinnedAutobahnRegistry(members[registryPath], PinnedAutobahnRegistryDigest, expansions)
}

func readPinnedAutobahnArchive(compressed []byte, archiveDigest string) (map[string][]byte, error) {
	if len(compressed) == 0 || len(compressed) > 16<<20 || archiveDigest != PinnedAutobahnSourceArchiveDigest || intake.DigestBytes(compressed) != archiveDigest {
		return nil, finding("AUTOBAHN_ARCHIVE_DIGEST_MISMATCH", "$", "archive must equal the accepted pinned source bytes")
	}
	gzipReader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, finding("INVALID_AUTOBAHN_ARCHIVE", "$", "archive is not valid gzip data")
	}
	tarBytes, err := io.ReadAll(io.LimitReader(gzipReader, 64<<20+1))
	closeErr := gzipReader.Close()
	if err != nil || closeErr != nil || len(tarBytes) == 0 || len(tarBytes) > 64<<20 {
		return nil, finding("INVALID_AUTOBAHN_ARCHIVE", "$", "expanded archive exceeds its bound or is truncated")
	}
	requiredPaths := make(map[string]string)
	for _, member := range pinnedAutobahnGeneratorMembers {
		requiredPaths[member.path] = member.digest
	}
	registryPath := pinnedAutobahnCaseDirectory + "/__init__.py"
	requiredPaths[registryPath] = PinnedAutobahnRegistryDigest
	requiredPaths[pinnedAutobahnReportSourcePath] = PinnedAutobahnReportSourceDigest
	members, err := validateAndReadAutobahnTar(tarBytes, pinnedAutobahnArchiveRoot, requiredPaths)
	if err != nil {
		return nil, err
	}
	return members, nil
}

func verifyPinnedAutobahnReportContract(source []byte) error {
	if len(source) == 0 || intake.DigestBytes(source) != PinnedAutobahnReportSourceDigest {
		return finding("AUTOBAHN_REPORT_SOURCE_MISMATCH", "$.archive.fuzzing", "report implementation must equal the accepted source member")
	}
	return verifyAutobahnReportSemantics(string(source))
}

func verifyAutobahnReportSemantics(text string) error {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	required := []string{
		`elif self.path == "/updateReports":`,
		`self.factory.createReports()`,
		`report_filename = "index.json"`,
		`report_filename = "index.html"`,
		`return self.cleanForFilename(agentId) + "_case_" + c + "." + ext`,
		"self.createReports()\n            reactor.stop()",
	}
	for _, fragment := range required {
		if strings.Count(text, fragment) < 1 {
			return finding("AUTOBAHN_REPORT_CONTRACT_UNRESOLVED", "$.archive.fuzzing", "accepted source does not prove the fixed one-case report lifecycle and filenames")
		}
	}
	return nil
}

func derivePinnedAutobahnExpansions(archiveDigest string, members map[string][]byte) (map[string]RegistryExpansion, error) {
	expansions := make(map[string]RegistryExpansion, len(pinnedAutobahnGeneratorMembers))
	for name, member := range pinnedAutobahnGeneratorMembers {
		ids, err := deriveAutobahnGeneratorIDs(name, members[member.path])
		if err != nil {
			return nil, err
		}
		expansions[name] = RegistryExpansion{ArchiveDigest: archiveDigest, MemberPath: member.path, SourceDigest: member.digest, CaseIDs: ids, sourceValidated: true, caseIDsDigest: digestStringSlice(ids)}
	}
	return expansions, nil
}

func validateAndReadAutobahnTar(tarBytes []byte, expectedRoot string, requiredPaths map[string]string) (map[string][]byte, error) {
	if len(tarBytes) == 0 || len(tarBytes) > 64<<20 || expectedRoot == "" || len(requiredPaths) == 0 {
		return nil, finding("INVALID_AUTOBAHN_ARCHIVE", "$", "tar bytes, exact root, and required members must be bounded")
	}
	for memberPath, digest := range requiredPaths {
		if !strings.HasPrefix(memberPath, expectedRoot+"/") || !isDigest(digest) {
			return nil, finding("UNKNOWN_AUTOBAHN_ARCHIVE_STRUCTURE", memberPath, "required member declaration leaves the exact pinned root or lacks a digest")
		}
	}
	reader := tar.NewReader(bytes.NewReader(tarBytes))
	seen := make(map[string]string)
	members := make(map[string][]byte, len(requiredPaths))
	protectedPrefix := pinnedAutobahnCaseDirectory + "/"
	if expectedRoot != pinnedAutobahnArchiveRoot {
		protectedPrefix = path.Dir(sortedFirstKey(requiredPaths)) + "/"
	}
	entries := 0
	var total int64
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, finding("INVALID_AUTOBAHN_ARCHIVE", "$", err.Error())
		}
		entries++
		if entries > 10000 || header.Size < 0 || header.Size > 16<<20 || total > 64<<20-header.Size {
			return nil, finding("ARCHIVE_LIMIT_EXCEEDED", header.Name, "archive exceeds fixed entry or byte bounds")
		}
		if header.Typeflag == tar.TypeXGlobalHeader && header.Name == "pax_global_header" {
			continue
		}
		name := strings.TrimSuffix(header.Name, "/")
		if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || path.Clean(name) != name || strings.Contains(name, "../") || len(strings.Split(name, "/")) > 32 {
			return nil, finding("PATH_TRAVERSAL", header.Name, "archive path is not a clean bounded relative path")
		}
		for _, character := range name {
			if character > 0x7f || character == 0 {
				return nil, finding("NORMALIZATION_COLLISION", header.Name, "archive paths must be ASCII for exact comparison")
			}
		}
		key := strings.ToLower(name)
		if prior, duplicate := seen[key]; duplicate {
			if prior == name {
				return nil, finding("DUPLICATE_ARCHIVE_ENTRY", name, "duplicate archive path")
			}
			return nil, finding("NORMALIZATION_COLLISION", name, "archive path collides with "+prior)
		}
		seen[key] = name
		if name != expectedRoot && !strings.HasPrefix(name, expectedRoot+"/") {
			return nil, finding("UNKNOWN_AUTOBAHN_ARCHIVE_STRUCTURE", name, "archive member leaves the exact pinned root")
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			if strings.HasPrefix(name, protectedPrefix) {
				return nil, finding("UNSAFE_ARCHIVE_ENTRY", name, "links and special files are forbidden in the generator source subtree")
			}
			// The accepted repository tarball contains unrelated links. Because
			// no archive member is extracted or followed and the outer digest is
			// fixed, they are inert metadata outside the generator subtree.
			continue
		}
		total += header.Size
		if _, wanted := requiredPaths[name]; !wanted {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(reader, 16<<20+1))
		if err != nil || int64(len(data)) != header.Size || len(data) > 16<<20 || intake.DigestBytes(data) != requiredPaths[name] {
			return nil, finding("AUTOBAHN_MEMBER_DIGEST_MISMATCH", name, "required generator bytes differ from their pinned digest")
		}
		members[name] = data
	}
	if len(members) != len(requiredPaths) {
		for memberPath := range requiredPaths {
			if members[memberPath] == nil {
				return nil, finding("AUTOBAHN_MEMBER_DIGEST_MISMATCH", memberPath, "required generator or registry member is missing")
			}
		}
	}
	return members, nil
}

func sortedFirstKey(values map[string]string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys[0]
}

func deriveAutobahnGeneratorIDs(name string, source []byte) ([]string, error) {
	if len(source) == 0 || len(source) > maxManifestBytes || !utf8.Valid(source) || strings.ContainsRune(string(source), 0) {
		return nil, finding("INVALID_AUTOBAHN_EXPANSION", "$.expansions."+name, "generator source is not bounded UTF-8")
	}
	text := strings.ReplaceAll(string(source), "\r\n", "\n")
	var ids []string
	switch name {
	case "Case6_X_X":
		counts, err := deriveCase6Counts(text)
		if err != nil {
			return nil, err
		}
		for group, count := range counts {
			for item := 1; item <= count; item++ {
				ids = append(ids, fmt.Sprintf("6.%d.%d", group+5, item))
			}
		}
	case "Case7_7_X", "Case7_9_X":
		family := strings.ReplaceAll(strings.TrimSuffix(strings.TrimPrefix(name, "Case"), "_X"), "_", ".")
		count, err := countPythonListItems(text, "tests")
		if err != nil || !strings.Contains(text, `type("`+name[:len(name)-1]+`%d" % i`) || !strings.Contains(text, "for s in tests:") {
			return nil, finding("INVALID_AUTOBAHN_EXPANSION", "$.expansions."+name, "close-code generator does not match its pinned static form")
		}
		ids = sequentialCaseIDs(family, count)
	case "Case9_7_X", "Case9_8_X":
		count, err := countPythonListItems(text, "tests")
		if err != nil || !strings.Contains(text, `cc = "Case9_7_%d"`) || !strings.Contains(text, `cc = "Case9_8_%d"`) || !strings.Contains(text, "for b in [False, True]:") {
			return nil, finding("INVALID_AUTOBAHN_EXPANSION", "$.expansions."+name, "performance generator does not match its pinned static form")
		}
		family := "9.7"
		if name == "Case9_8_X" {
			family = "9.8"
		}
		ids = sequentialCaseIDs(family, count)
	case "Case12_X_X", "Case13_X_X":
		messageSizes, err := countPythonListItems(text, "MSG_SIZES")
		if err != nil || messageSizes == 0 {
			return nil, finding("INVALID_AUTOBAHN_EXPANSION", "$.expansions."+name, "compression size inventory is not statically recognizable")
		}
		outer := 0
		family := 12
		if name == "Case12_X_X" {
			outer, err = countPythonListItems(text, "WS_COMPRESSION_TESTDATA_KEYS")
			if !strings.Contains(text, `cc = "Case12_%d_%d" % (j, i)`) {
				err = fmt.Errorf("missing Case12 type form")
			}
		} else {
			family = 13
			outer, err = countPythonListItems(text, "DEFLATE_PARAMS")
			if !strings.Contains(text, `cc = "Case13_%d_%d" % (j, i)`) {
				err = fmt.Errorf("missing Case13 type form")
			}
		}
		if err != nil || outer == 0 {
			return nil, finding("INVALID_AUTOBAHN_EXPANSION", "$.expansions."+name, "compression generator does not match its pinned static form")
		}
		for group := 1; group <= outer; group++ {
			for item := 1; item <= messageSizes; item++ {
				ids = append(ids, fmt.Sprintf("%d.%d.%d", family, group, item))
			}
		}
	default:
		return nil, finding("UNKNOWN_AUTOBAHN_EXPANSION", "$.expansions."+name, "generator family is not pinned")
	}
	if len(ids) == 0 || len(ids) > 100000 {
		return nil, finding("INVALID_AUTOBAHN_EXPANSION", "$.expansions."+name, "generator produced no bounded exact identities")
	}
	return ids, nil
}

func sequentialCaseIDs(family string, count int) []string {
	ids := make([]string, count)
	for index := range ids {
		ids[index] = fmt.Sprintf("%s.%d", family, index+1)
	}
	return ids
}

func countPythonListItems(source, variable string) (int, error) {
	pattern := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(variable) + `\s*=\s*\[`)
	location := pattern.FindStringIndex(source)
	if location == nil {
		return 0, fmt.Errorf("missing %s list", variable)
	}
	start := location[1]
	depth := 1
	inString := byte(0)
	escaped := false
	end := -1
	for index := start; index < len(source); index++ {
		character := source[index]
		if inString != 0 {
			if escaped {
				escaped = false
			} else if character == '\\' {
				escaped = true
			} else if character == inString {
				inString = 0
			}
			continue
		}
		if character == '\'' || character == '"' {
			inString = character
			continue
		}
		if character == '[' {
			depth++
		} else if character == ']' {
			depth--
			if depth == 0 {
				end = index
				break
			}
		}
	}
	if end < 0 || inString != 0 {
		return 0, fmt.Errorf("unbalanced %s list", variable)
	}
	body := strings.TrimSpace(source[start:end])
	if body == "" {
		return 0, fmt.Errorf("empty %s list", variable)
	}
	depth = 0
	var quote rune
	escaped = false
	count := 1
	for _, character := range body {
		if quote != 0 {
			if escaped {
				escaped = false
			} else if character == '\\' {
				escaped = true
			} else if character == quote {
				quote = 0
			}
			continue
		}
		if character == '\'' || character == '"' {
			quote = character
			continue
		}
		switch character {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				count++
			}
		}
		if depth < 0 {
			return 0, fmt.Errorf("unbalanced %s list", variable)
		}
	}
	if depth != 0 || quote != 0 {
		return 0, fmt.Errorf("unbalanced %s list", variable)
	}
	if strings.HasSuffix(strings.TrimSpace(body), ",") {
		count--
	}
	return count, nil
}

func deriveCase6Counts(source string) ([]int, error) {
	if !strings.Contains(source, "Case6_X_X = []") || !strings.Contains(source, `type("Case6_%d_%d" % (i, j)`) || !strings.Contains(source, "i = 5\nfor t in createUtf8TestSequences():") {
		return nil, finding("INVALID_AUTOBAHN_EXPANSION", "$.expansions.Case6_X_X", "UTF-8 generator does not match its pinned static form")
	}
	functionStart := strings.Index(source, "def createUtf8TestSequences():")
	functionEnd := strings.Index(source[functionStart:], "\n   return UTF8_TEST_SEQUENCES")
	if functionStart < 0 || functionEnd < 0 {
		return nil, finding("INVALID_AUTOBAHN_EXPANSION", "$.expansions.Case6_X_X", "UTF-8 sequence factory is missing")
	}
	body := source[functionStart : functionStart+functionEnd]
	groups := strings.Split(body, "UTF8_TEST_SEQUENCES.append(vs)")
	if len(groups) != 20 {
		return nil, finding("INVALID_AUTOBAHN_EXPANSION", "$.expansions.Case6_X_X", "UTF-8 sequence group count changed")
	}
	counts := make([]int, 0, 19)
	for index := 0; index < 19; index++ {
		group := groups[index]
		if marker := strings.LastIndex(group, `vs = [`); marker >= 0 {
			group = group[marker:]
		}
		count := strings.Count(group, "vs[1].append(")
		switch {
		case strings.Contains(group, "for i in xrange(1, len(vss) + 1):"):
			literal := regexp.MustCompile(`(?m)^\s*vss = ('(?:\\.|[^'])*')`).FindStringSubmatch(body)
			if len(literal) != 2 {
				return nil, finding("INVALID_AUTOBAHN_EXPANSION", "$.expansions.Case6_X_X", "UTF-8 prefix seed is not statically recognizable")
			}
			decoded, err := strconv.Unquote(`"` + strings.ReplaceAll(literal[1][1:len(literal[1])-1], `"`, `\"`) + `"`)
			if err != nil {
				return nil, finding("INVALID_AUTOBAHN_EXPANSION", "$.expansions.Case6_X_X", "UTF-8 prefix seed is invalid")
			}
			count = len(decoded)
		case strings.Contains(group, "for i in xrange(0x80, 0xbf):"):
			if count != 8 {
				return nil, finding("INVALID_AUTOBAHN_EXPANSION", "$.expansions.Case6_X_X", "continuation-byte generator changed")
			}
		case strings.Contains(group, "for mm in m:"):
			count = 5
			if !strings.Contains(group, "m = [(0xc0, 0xdf), (0xe0, 0xef), (0xf0, 0xf7), (0xf8, 0xfb), (0xfc, 0xfd)]") {
				return nil, finding("INVALID_AUTOBAHN_EXPANSION", "$.expansions.Case6_X_X", "lonely-start inventory changed")
			}
		case strings.Contains(group, "for kk in k:"):
			count = 10
			if !strings.Contains(group, "k = ['\\xc0', '\\xe0\\x80', '\\xf0\\x80\\x80', '\\xf8\\x80\\x80\\x80', '\\xfc\\x80\\x80\\x80\\x80',") {
				return nil, finding("INVALID_AUTOBAHN_EXPANSION", "$.expansions.Case6_X_X", "incomplete-sequence inventory changed")
			}
		case strings.Contains(group, "for z1 in"):
			if !strings.Contains(group, "for z1 in ['\\xf0', '\\xf1', '\\xf2', '\\xf3', '\\xf4']:") || !strings.Contains(group, "for z2 in ['\\x8f', '\\x9f', '\\xaf', '\\xbf']:") || !strings.Contains(group, "for z3 in ['\\xbe', '\\xbf']:") || !strings.Contains(group, "if not (z1 == '\\xf4' and z2 != '\\x8f'):") || !strings.Contains(group, "if zz not in ['\\xf0\\x8f\\xbf\\xbe', '\\xf0\\x8f\\xbf\\xbf']:") {
				return nil, finding("INVALID_AUTOBAHN_EXPANSION", "$.expansions.Case6_X_X", "non-character generator changed")
			}
			count = 34
		default:
			if strings.Contains(group, "\n   for ") {
				return nil, finding("INVALID_AUTOBAHN_EXPANSION", "$.expansions.Case6_X_X", "unrecognized UTF-8 generator loop")
			}
		}
		if count <= 0 || count > 10000 {
			return nil, finding("INVALID_AUTOBAHN_EXPANSION", "$.expansions.Case6_X_X", "UTF-8 sequence count is invalid")
		}
		counts = append(counts, count)
	}
	return counts, nil
}

// ParsePinnedAutobahnRegistry derives identities from the accepted registry
// source text without importing or executing it. Dynamic Case*_X families
// require exact, digest-bound static expansion inputs.
func ParsePinnedAutobahnRegistry(raw []byte, sourceDigest string, expansions map[string]RegistryExpansion) (AutobahnRegistry, error) {
	if len(raw) == 0 || len(raw) > maxManifestBytes || !utf8.Valid(raw) || strings.ContainsRune(string(raw), 0) || !isDigest(sourceDigest) || intake.DigestBytes(raw) != sourceDigest {
		return AutobahnRegistry{}, finding("INVALID_AUTOBAHN_REGISTRY_SOURCE", "$", "registry source must be bounded UTF-8 bytes matching its accepted digest")
	}
	tokens := autobahnPythonTokenPattern.FindAllStringSubmatch(string(raw), -1)
	if len(tokens) == 0 {
		return AutobahnRegistry{}, finding("INVALID_AUTOBAHN_REGISTRY_SOURCE", "$", "registry source contains no statically recognizable Case identifiers")
	}
	caseSet := make(map[string]struct{})
	usedExpansion := make(map[string]struct{})
	unresolved := make([]string, 0)
	for _, token := range tokens {
		name := "Case" + token[1]
		if strings.Contains(token[1], "X") {
			expansion, exists := expansions[name]
			if !exists {
				unresolved = append(unresolved, name)
				continue
			}
			member, pinned := pinnedAutobahnGeneratorMembers[name]
			if !pinned || !expansion.sourceValidated || expansion.ArchiveDigest != PinnedAutobahnSourceArchiveDigest || expansion.MemberPath != member.path || expansion.SourceDigest != member.digest || len(expansion.CaseIDs) == 0 || expansion.caseIDsDigest != digestStringSlice(expansion.CaseIDs) {
				return AutobahnRegistry{}, finding("INVALID_AUTOBAHN_EXPANSION", "$.expansions."+name, "expansion must derive from the exact accepted archive member")
			}
			prefix := generatorCasePrefix(name)
			for index, id := range expansion.CaseIDs {
				if !autobahnCasePattern.MatchString(id) || !strings.HasPrefix(id, prefix) {
					return AutobahnRegistry{}, finding("INVALID_AUTOBAHN_EXPANSION", fmt.Sprintf("$.expansions.%s.case_ids[%d]", name, index), "expanded ID is not exact or leaves its generator family")
				}
				caseSet[id] = struct{}{}
			}
			usedExpansion[name] = struct{}{}
			continue
		}
		id := strings.ReplaceAll(token[1], "_", ".")
		if !autobahnCasePattern.MatchString(id) {
			return AutobahnRegistry{}, finding("UNCLASSIFIED_AUTOBAHN_FAMILY", "$.registry_source", "static registry contains case outside the frozen selected/excluded families: "+id)
		}
		caseSet[id] = struct{}{}
	}
	for name := range expansions {
		if _, used := usedExpansion[name]; !used {
			return AutobahnRegistry{}, finding("UNKNOWN_AUTOBAHN_EXPANSION", "$.expansions."+name, "expansion does not bind a generator visible in pinned registry source")
		}
	}
	if len(unresolved) != 0 {
		sort.Strings(unresolved)
		unresolved = compactStrings(unresolved)
		return AutobahnRegistry{}, finding("UNRESOLVED_AUTOBAHN_GENERATOR", "$.unresolved_generators", "exact expansions required for "+strings.Join(unresolved, ","))
	}
	caseIDs := make([]string, 0, len(caseSet))
	for id := range caseSet {
		caseIDs = append(caseIDs, id)
	}
	sort.Strings(caseIDs)
	registry := AutobahnRegistry{SchemaVersion: "1.0.0", SourceDigest: sourceDigest, CaseIDs: caseIDs, UnresolvedGenerators: []string{}, sourceValidated: true, caseIDsDigest: digestStringSlice(caseIDs)}
	return registry, registry.Validate()
}

func generatorCasePrefix(name string) string {
	value := strings.TrimPrefix(name, "Case")
	value = strings.TrimSuffix(value, "_X_X")
	value = strings.TrimSuffix(value, "_X")
	return strings.ReplaceAll(value, "_", ".") + "."
}

func digestStringSlice(values []string) string {
	raw, err := intake.CanonicalJSON(values)
	if err != nil {
		return ""
	}
	return intake.DigestBytes(raw)
}

func (r AutobahnRegistry) Validate() error {
	if r.SchemaVersion != "1.0.0" || !isDigest(r.SourceDigest) || len(r.CaseIDs) == 0 || len(r.CaseIDs) > 100000 {
		return finding("INVALID_AUTOBAHN_REGISTRY", "$", "registry schema, source digest, or case count is invalid")
	}
	if len(r.UnresolvedGenerators) != 0 {
		return finding("UNRESOLVED_AUTOBAHN_GENERATOR", "$.unresolved_generators", "generated Case*_X families must be statically expanded to exact case identities")
	}
	seen := make(map[string]struct{}, len(r.CaseIDs))
	for index, id := range r.CaseIDs {
		if !autobahnCasePattern.MatchString(id) || strings.ContainsAny(id, "*Xx") {
			return finding("INVALID_AUTOBAHN_CASE_ID", fmt.Sprintf("$.case_ids[%d]", index), "case identity must be fully expanded dotted numerics in an allowed family")
		}
		if _, duplicate := seen[id]; duplicate {
			return finding("DUPLICATE_ENTRY", fmt.Sprintf("$.case_ids[%d]", index), "Autobahn case occurs more than once")
		}
		seen[id] = struct{}{}
	}
	return nil
}

type AutobahnSelection struct {
	SchemaVersion    string   `json:"schema_version"`
	RegistryDigest   string   `json:"registry_digest"`
	SelectedFamilies []string `json:"selected_families"`
	ExcludedFamilies []string `json:"excluded_families"`
	SelectedCaseIDs  []string `json:"selected_case_ids"`
	ExcludedCaseIDs  []string `json:"excluded_case_ids"`
}

func SelectAutobahnRegistry(registry AutobahnRegistry) (AutobahnSelection, error) {
	if err := registry.Validate(); err != nil {
		return AutobahnSelection{}, err
	}
	if !registry.sourceValidated {
		return AutobahnSelection{}, finding("AUTOBAHN_REGISTRY_PROVENANCE_REQUIRED", "$", "registry identities must come from static parsing of pinned source bytes")
	}
	if registry.caseIDsDigest != digestStringSlice(registry.CaseIDs) {
		return AutobahnSelection{}, finding("AUTOBAHN_REGISTRY_PROVENANCE_REQUIRED", "$.case_ids", "registry identities changed after static parsing")
	}
	bytes, err := intake.CanonicalJSON(registry)
	if err != nil {
		return AutobahnSelection{}, err
	}
	selection := AutobahnSelection{
		SchemaVersion: "1.0.0", RegistryDigest: intake.DigestBytes(bytes),
		SelectedFamilies: append([]string(nil), selectedAutobahnFamilies...),
		ExcludedFamilies: append([]string(nil), excludedAutobahnFamilies...),
	}
	selectedSeen := make(map[string]bool)
	excludedSeen := make(map[string]bool)
	for _, id := range registry.CaseIDs {
		family := strings.SplitN(id, ".", 2)[0] + ".*"
		if contains(selectedAutobahnFamilies, family) {
			selection.SelectedCaseIDs = append(selection.SelectedCaseIDs, id)
			selectedSeen[family] = true
		} else if contains(excludedAutobahnFamilies, family) {
			selection.ExcludedCaseIDs = append(selection.ExcludedCaseIDs, id)
			excludedSeen[family] = true
		} else {
			return AutobahnSelection{}, finding("UNCLASSIFIED_AUTOBAHN_FAMILY", "$.case_ids", "registry contains a family outside the frozen selected/excluded policy")
		}
	}
	for _, family := range selectedAutobahnFamilies {
		if !selectedSeen[family] {
			return AutobahnSelection{}, finding("MISSING_AUTOBAHN_FAMILY", "$.selected_families", "selected family "+family+" has no exact registry identities")
		}
	}
	for _, family := range excludedAutobahnFamilies {
		if !excludedSeen[family] {
			return AutobahnSelection{}, finding("MISSING_AUTOBAHN_EXCLUSION", "$.excluded_families", "excluded family "+family+" is not visibly represented")
		}
	}
	sort.Strings(selection.SelectedCaseIDs)
	sort.Strings(selection.ExcludedCaseIDs)
	return selection, nil
}

type AutobahnResult struct {
	CaseID            string `json:"case_id"`
	Status            string `json:"status"`
	ResultDigest      string `json:"result_digest"`
	ObservationDigest string `json:"observation_digest"`
	BindingDigest     string `json:"binding_digest"`
}

var terminalAutobahnStatuses = map[string]struct{}{
	"OK": {}, "FAILED": {}, "NON-STRICT": {}, "INFORMATIONAL": {}, "UNIMPLEMENTED": {},
}

type autobahnResultBinding struct {
	SchemaVersion     string `json:"schema_version"`
	Mode              string `json:"mode"`
	CaseID            string `json:"case_id"`
	Status            string `json:"status"`
	ResultDigest      string `json:"result_digest"`
	ObservationDigest string `json:"observation_digest"`
}

func AutobahnResultBindingDigest(mode string, result AutobahnResult) (string, error) {
	if mode != "client" && mode != "server" {
		return "", finding("INVALID_AUTOBAHN_MODE", "$.mode", "mode must be client or server")
	}
	if !autobahnCasePattern.MatchString(result.CaseID) || !isDigest(result.ResultDigest) || !isDigest(result.ObservationDigest) {
		return "", finding("INVALID_AUTOBAHN_RESULT", "$.result", "case and result/observation digests must be exact")
	}
	if _, terminal := terminalAutobahnStatuses[result.Status]; !terminal {
		return "", finding("NONTERMINAL_AUTOBAHN_STATUS", "$.result.status", "status must equal an exact terminal Autobahn behavior")
	}
	data, err := intake.CanonicalJSON(autobahnResultBinding{
		SchemaVersion: "1.0.0", Mode: mode, CaseID: result.CaseID, Status: result.Status,
		ResultDigest: result.ResultDigest, ObservationDigest: result.ObservationDigest,
	})
	if err != nil {
		return "", err
	}
	return intake.DigestBytes(data), nil
}

func ReconcileAutobahn(registry AutobahnRegistry, selection AutobahnSelection, mode string, results []AutobahnResult) error {
	derived, err := SelectAutobahnRegistry(registry)
	if err != nil {
		return err
	}
	left, err := intake.CanonicalJSON(selection)
	if err != nil {
		return err
	}
	right, err := intake.CanonicalJSON(derived)
	if err != nil {
		return err
	}
	if !bytes.Equal(left, right) {
		return finding("AUTOBAHN_SELECTION_DRIFT", "$", "selection does not exactly derive from the statically parsed registry")
	}
	if selection.SchemaVersion != "1.0.0" || !isDigest(selection.RegistryDigest) || !equalStrings(selection.SelectedFamilies, selectedAutobahnFamilies) || !equalStrings(selection.ExcludedFamilies, excludedAutobahnFamilies) {
		return finding("AUTOBAHN_SELECTION_DRIFT", "$", "selection policy differs from the frozen families")
	}
	if mode != "client" && mode != "server" {
		return finding("INVALID_AUTOBAHN_MODE", "$.mode", "mode must be client or server")
	}
	expected, err := exactSet(selection.SelectedCaseIDs, "$.selected_case_ids", 100000)
	if err != nil {
		return err
	}
	excluded, err := exactSet(selection.ExcludedCaseIDs, "$.excluded_case_ids", 100000)
	if err != nil {
		return err
	}
	for id := range expected {
		if _, conflict := excluded[id]; conflict {
			return finding("AUTOBAHN_SELECTION_DRIFT", "$.excluded_case_ids", "case is both selected and excluded")
		}
	}
	if len(results) != len(expected) {
		return finding("AUTOBAHN_RESULT_MISMATCH", "$.results", "executed result count differs from exact selected inventory")
	}
	seen := make(map[string]struct{}, len(results))
	for index, result := range results {
		if _, exists := expected[result.CaseID]; !exists {
			return finding("AUTOBAHN_RESULT_MISMATCH", fmt.Sprintf("$.results[%d]", index), "result is unknown or excluded")
		}
		if _, duplicate := seen[result.CaseID]; duplicate {
			return finding("DUPLICATE_ENTRY", fmt.Sprintf("$.results[%d].case_id", index), "case has more than one result")
		}
		binding, err := AutobahnResultBindingDigest(mode, result)
		if err != nil {
			return err
		}
		if result.BindingDigest != binding {
			return finding("AUTOBAHN_RESULT_BINDING_MISMATCH", fmt.Sprintf("$.results[%d].binding_digest", index), "binding digest does not cover the exact mode, case, status, result, and observation")
		}
		seen[result.CaseID] = struct{}{}
	}
	return nil
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func compactStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}
