// Package divergencesweep compares the pinned Java 1.6.0 baseline against the
// Rust port on the four legs of the native x86_64 Autobahn provenance run,
// field by field, on everything the existing evidence does NOT compare.
//
// Autobahn scoring reduces a case to a coarse behaviour class (behavior,
// behaviorClose). The committed per-case comparison at
// evidence/autobahn/native-x86_64-provenance/comparison/java-vs-rust-per-case.json
// compares exactly those two fields. The public-corpus differential scores a
// core-level transcript and never sees the Autobahn wire at all. Nothing in
// this repository compared the close CODE the subject sent, the close REASON
// string it sent, or which peer closed the TCP connection, case by case.
// That is what this package does.
//
// Everything here is recomputed from the committed report bytes on every run.
// No committed summary is trusted: the digest manifest is verified against the
// files it pins, each leg's index.json is cross-checked against the per-case
// reports it indexes, and the recomputed behaviour classes are cross-checked
// against the independently produced comparison document.
package divergencesweep

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// EvidenceRoot is the committed root of the native x86_64 provenance run,
// relative to the repository root.
const EvidenceRoot = "evidence/autobahn/native-x86_64-provenance"

// DigestManifestPath pins every file under EvidenceRoot.
const DigestManifestPath = "evidence/autobahn/native-digest-manifest.json"

// ComparisonPath is the independently produced per-case behaviour-class
// comparison this package cross-checks its own role mapping against.
const ComparisonPath = EvidenceRoot + "/comparison/java-vs-rust-per-case.json"

// DocumentPath is the committed sweep document this package emits and verifies.
const DocumentPath = "evidence/java/observed-close-divergences.json"

// ExpectedCaseCount is the size of the pinned Autobahn case manifest every leg
// walked. It is asserted, never assumed: a leg with a different count is an
// error, not a smaller comparison.
const ExpectedCaseCount = 247

// LegSpec names one of the four legs of the run.
type LegSpec struct {
	// Peer is the subject implementation: "rust" (the port) or "java" (the
	// pinned 1.6.0 baseline).
	Peer string
	// Directory is the leg directory under the peer directory.
	Directory string
	// SubjectRole is the role the SUBJECT played. The Autobahn suite names
	// its legs after the role the SUITE plays, so a "fuzzingclient" leg has
	// the suite as client and the subject as server. This field is checked
	// against the reports' own isServer flag, not taken on trust.
	SubjectRole string
}

// Legs is the closed set of four legs the run produced.
func Legs() []LegSpec {
	return []LegSpec{
		{Peer: "rust", Directory: "fuzzingclient-run1", SubjectRole: "server"},
		{Peer: "java", Directory: "fuzzingclient-run1", SubjectRole: "server"},
		{Peer: "rust", Directory: "fuzzingserver-run1", SubjectRole: "client"},
		{Peer: "java", Directory: "fuzzingserver-run1", SubjectRole: "client"},
	}
}

// Leg is one loaded leg: its agent name and every per-case report, parsed.
type Leg struct {
	Spec  LegSpec
	Agent string
	// IDs is the sorted case-identity list the leg reported.
	IDs []string
	// Cases maps a case identity to the decoded report object. Numbers are
	// json.Number so a comparison never depends on float formatting.
	Cases map[string]map[string]any
}

// indexEntry is the subset of a leg index.json entry this package binds the
// per-case reports to. The index is written by a different pass of the suite
// than the per-case reports, so it is an in-run second source for these four
// fields, and a per-case report edited on its own contradicts it.
type indexEntry struct {
	Behavior        *string      `json:"behavior"`
	BehaviorClose   *string      `json:"behaviorClose"`
	Duration        *json.Number `json:"duration"`
	RemoteCloseCode *json.Number `json:"remoteCloseCode"`
	ReportFile      string       `json:"reportfile"`
}

func decodeJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	return decoder.Decode(target)
}

// LoadLeg reads one leg and binds it to itself: the case files present on
// disk, the case files the index names, and the four fields the index repeats
// must all agree, and every case must carry the leg's own agent name.
func LoadLeg(root string, spec LegSpec) (*Leg, error) {
	legDir := filepath.Join(root, EvidenceRoot, spec.Peer, spec.Directory)
	indexBytes, err := os.ReadFile(filepath.Join(legDir, "index.json"))
	if err != nil {
		return nil, fmt.Errorf("leg %s/%s: index: %w", spec.Peer, spec.Directory, err)
	}
	var index map[string]map[string]indexEntry
	if err := decodeJSON(indexBytes, &index); err != nil {
		return nil, fmt.Errorf("leg %s/%s: index: %w", spec.Peer, spec.Directory, err)
	}
	if len(index) != 1 {
		return nil, fmt.Errorf("leg %s/%s: index names %d agents, want exactly 1",
			spec.Peer, spec.Directory, len(index))
	}
	agent := ""
	for name := range index {
		agent = name
	}
	entries := index[agent]
	if len(entries) != ExpectedCaseCount {
		return nil, fmt.Errorf("leg %s/%s: index holds %d cases, want %d",
			spec.Peer, spec.Directory, len(entries), ExpectedCaseCount)
	}

	casesDir := filepath.Join(legDir, "cases")
	onDisk, err := os.ReadDir(casesDir)
	if err != nil {
		return nil, fmt.Errorf("leg %s/%s: cases: %w", spec.Peer, spec.Directory, err)
	}
	present := map[string]bool{}
	for _, entry := range onDisk {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		present[entry.Name()] = true
	}
	named := map[string]bool{}
	for _, entry := range entries {
		named[entry.ReportFile] = true
	}
	if len(present) != len(named) {
		return nil, fmt.Errorf("leg %s/%s: %d case files on disk, %d named by the index",
			spec.Peer, spec.Directory, len(present), len(named))
	}
	for name := range named {
		if !present[name] {
			return nil, fmt.Errorf("leg %s/%s: index names %s, which is not on disk",
				spec.Peer, spec.Directory, name)
		}
	}

	leg := &Leg{Spec: spec, Agent: agent, Cases: map[string]map[string]any{}}
	for caseID, entry := range entries {
		reportBytes, err := os.ReadFile(filepath.Join(casesDir, entry.ReportFile))
		if err != nil {
			return nil, fmt.Errorf("leg %s/%s case %s: %w", spec.Peer, spec.Directory, caseID, err)
		}
		var report map[string]any
		if err := decodeJSON(reportBytes, &report); err != nil {
			return nil, fmt.Errorf("leg %s/%s case %s: %w", spec.Peer, spec.Directory, caseID, err)
		}
		if got, _ := report["id"].(string); got != caseID {
			return nil, fmt.Errorf("leg %s/%s: %s reports id %q, indexed as %q",
				spec.Peer, spec.Directory, entry.ReportFile, got, caseID)
		}
		if got, _ := report["agent"].(string); got != agent {
			return nil, fmt.Errorf("leg %s/%s case %s: report agent %q, index agent %q",
				spec.Peer, spec.Directory, caseID, got, agent)
		}
		if err := bindIndexEntry(spec, caseID, entry, report); err != nil {
			return nil, err
		}
		leg.Cases[caseID] = report
		leg.IDs = append(leg.IDs, caseID)
	}
	sort.Strings(leg.IDs)

	// The subject's role is read out of the reports, not assumed from the leg
	// name: isServer is the SUITE's role, so the subject's is its complement.
	suiteIsServer, err := singleBool(leg, "isServer")
	if err != nil {
		return nil, err
	}
	derived := "server"
	if suiteIsServer {
		derived = "client"
	}
	if derived != spec.SubjectRole {
		return nil, fmt.Errorf("leg %s/%s: reports say the subject role is %q, the leg is declared %q",
			spec.Peer, spec.Directory, derived, spec.SubjectRole)
	}
	return leg, nil
}

func bindIndexEntry(spec LegSpec, caseID string, entry indexEntry, report map[string]any) error {
	mismatch := func(field string, indexed, reported any) error {
		return fmt.Errorf("leg %s/%s case %s: index %s=%v, per-case report %s=%v",
			spec.Peer, spec.Directory, caseID, field, indexed, field, reported)
	}
	if entry.Behavior == nil || *entry.Behavior != stringOf(report["behavior"]) {
		return mismatch("behavior", derefString(entry.Behavior), report["behavior"])
	}
	if entry.BehaviorClose == nil || *entry.BehaviorClose != stringOf(report["behaviorClose"]) {
		return mismatch("behaviorClose", derefString(entry.BehaviorClose), report["behaviorClose"])
	}
	if !sameNumber(entry.Duration, report["duration"]) {
		return mismatch("duration", derefNumber(entry.Duration), report["duration"])
	}
	if !sameNumber(entry.RemoteCloseCode, report["remoteCloseCode"]) {
		return mismatch("remoteCloseCode", derefNumber(entry.RemoteCloseCode), report["remoteCloseCode"])
	}
	return nil
}

func stringOf(value any) string {
	text, _ := value.(string)
	return text
}

func derefString(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func derefNumber(value *json.Number) any {
	if value == nil {
		return nil
	}
	return value.String()
}

// sameNumber compares an index number against a report number, treating a
// missing index value and a null report value as the same absence.
func sameNumber(indexed *json.Number, reported any) bool {
	if indexed == nil {
		return reported == nil
	}
	number, ok := reported.(json.Number)
	if !ok {
		return false
	}
	return number.String() == indexed.String()
}

func singleBool(leg *Leg, field string) (bool, error) {
	var value bool
	for i, caseID := range leg.IDs {
		got, ok := leg.Cases[caseID][field].(bool)
		if !ok {
			return false, fmt.Errorf("leg %s/%s case %s: %s is not a boolean",
				leg.Spec.Peer, leg.Spec.Directory, caseID, field)
		}
		if i == 0 {
			value = got
			continue
		}
		if got != value {
			return false, fmt.Errorf("leg %s/%s: %s is not constant across the leg",
				leg.Spec.Peer, leg.Spec.Directory, field)
		}
	}
	return value, nil
}

// manifestEntry is one file pinned by the native digest manifest.
type manifestEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type digestManifest struct {
	Root      string          `json:"root"`
	FileCount int             `json:"file_count"`
	Files     []manifestEntry `json:"files"`
}

// VerifyEvidenceIntegrity refuses to sweep a tree that is not the tree the
// digest manifest pins. It checks BOTH directions — every pinned file present
// with the pinned bytes, and no file under the root that the manifest does not
// pin — so neither an edited report nor a planted extra one passes.
func VerifyEvidenceIntegrity(root string) (int, error) {
	manifestBytes, err := os.ReadFile(filepath.Join(root, DigestManifestPath))
	if err != nil {
		return 0, fmt.Errorf("digest manifest: %w", err)
	}
	var manifest digestManifest
	if err := decodeJSON(manifestBytes, &manifest); err != nil {
		return 0, fmt.Errorf("digest manifest: %w", err)
	}
	if manifest.Root != EvidenceRoot {
		return 0, fmt.Errorf("digest manifest pins root %q, this sweep reads %q",
			manifest.Root, EvidenceRoot)
	}
	if manifest.FileCount != len(manifest.Files) {
		return 0, fmt.Errorf("digest manifest declares %d files and lists %d",
			manifest.FileCount, len(manifest.Files))
	}
	pinned := make(map[string]manifestEntry, len(manifest.Files))
	for _, entry := range manifest.Files {
		if _, duplicate := pinned[entry.Path]; duplicate {
			return 0, fmt.Errorf("digest manifest pins %s twice", entry.Path)
		}
		pinned[entry.Path] = entry
	}

	seen := map[string]bool{}
	walkRoot := filepath.Join(root, EvidenceRoot)
	err = filepath.Walk(walkRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		entry, ok := pinned[relative]
		if !ok {
			return fmt.Errorf("%s is under the evidence root and is not pinned by the digest manifest", relative)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if int64(len(data)) != entry.Bytes {
			return fmt.Errorf("%s is %d bytes, the manifest pins %d", relative, len(data), entry.Bytes)
		}
		sum := sha256.Sum256(data)
		if got := "sha256:" + hex.EncodeToString(sum[:]); got != entry.SHA256 {
			return fmt.Errorf("%s digests %s, the manifest pins %s", relative, got, entry.SHA256)
		}
		seen[relative] = true
		return nil
	})
	if err != nil {
		return 0, err
	}
	if len(seen) != len(pinned) {
		for path := range pinned {
			if !seen[path] {
				return 0, fmt.Errorf("the digest manifest pins %s, which is not under the evidence root", path)
			}
		}
	}
	return len(pinned), nil
}
