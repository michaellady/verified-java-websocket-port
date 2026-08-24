package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
	"github.com/michaellady/verified-java-websocket-port/internal/lab"
)

const maxInputBytes = int64(8 << 20)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 {
		printUsage(stderr)
		return 2
	}
	switch arguments[0] {
	case "verify-root":
		return runVerifyRoot(arguments[1:], stdout, stderr)
	case "verify-sandbox-plan":
		return runVerifySandboxPlan(arguments[1:], stdout, stderr)
	case "verify-test-inventory":
		return runVerifyTestInventory(arguments[1:], stdout, stderr)
	case "compare-observations":
		return runCompareObservations(arguments[1:], stdout, stderr)
	case "select-autobahn":
		return runSelectAutobahn(arguments[1:], stdout, stderr)
	case "verify-autobahn":
		return runVerifyAutobahn(arguments[1:], stdout, stderr)
	case "verify-ledger":
		return runVerifyLedger(arguments[1:], stdout, stderr)
	case "proxy-maven-central":
		return runMavenCentralProxy(arguments[1:], stdout, stderr)
	default:
		printUsage(stderr)
		return 2
	}
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage:")
	fmt.Fprintln(output, "  labctl verify-root --store-base DIR --root-digest SHA256")
	fmt.Fprintln(output, "  labctl verify-sandbox-plan --file FILE --store-base DIR --root-digest SHA256")
	fmt.Fprintln(output, "  labctl verify-test-inventory --file FILE")
	fmt.Fprintln(output, "  labctl compare-observations --first FILE --second FILE")
	fmt.Fprintln(output, "  labctl select-autobahn --registry-bundle FILE")
	fmt.Fprintln(output, "  labctl verify-autobahn --registry-bundle FILE --selection FILE --mode client|server --results FILE")
	fmt.Fprintln(output, "  labctl verify-ledger --ledger-dir DIR --observed FILE")
	fmt.Fprintln(output, "  labctl proxy-maven-central --listen 127.0.0.1:PORT")
}

func runMavenCentralProxy(arguments []string, stdout, stderr io.Writer) int {
	flags := newFlags("proxy-maven-central", stderr)
	listen := flags.String("listen", "", "explicit IPv4 loopback listener")
	if parseExact(flags, arguments) != nil || validateProxyListen(*listen) != nil {
		return 2
	}
	listener, err := net.Listen("tcp4", *listen)
	if err != nil {
		return writeDenied(stdout, &intake.Finding{Code: "MAVEN_PROXY_LISTENER_DENIED", Path: "$.listen", Message: "loopback listener cannot be opened"})
	}
	defer listener.Close()
	if err := writeJSON(stdout, map[string]any{
		"status": "READY",
		"result": map[string]any{"authority": lab.MavenCentralAuthority, "listen": listener.Addr().String()},
	}); err != nil {
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := lab.ServeMavenCentralProxy(ctx, listener, stdout); err != nil {
		return writeDenied(stdout, err)
	}
	return 0
}

func validateProxyListen(address string) error {
	host, portText, err := net.SplitHostPort(address)
	if err != nil || host != "127.0.0.1" {
		return fmt.Errorf("listener must be an explicit IPv4 loopback address")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return fmt.Errorf("listener port must be in 1..65535")
	}
	return nil
}

func runVerifyRoot(arguments []string, stdout, stderr io.Writer) int {
	flags := newFlags("verify-root", stderr)
	storeBase := flags.String("store-base", "", "absolute promotion-store root")
	rootDigest := flags.String("root-digest", "", "accepted root SHA-256 digest")
	if parseExact(flags, arguments) != nil || *storeBase == "" || *rootDigest == "" {
		return 2
	}
	root, err := lab.LoadAcceptedRoot(*storeBase, *rootDigest)
	if err != nil {
		return writeDenied(stdout, err)
	}
	return writeReady(stdout, map[string]any{"manifest": root.Manifest(), "object_count": len(root.Objects())})
}

func runVerifySandboxPlan(arguments []string, stdout, stderr io.Writer) int {
	flags := newFlags("verify-sandbox-plan", stderr)
	path := flags.String("file", "", "strict sandbox plan JSON")
	storeBase := flags.String("store-base", "", "absolute promotion-store root")
	rootDigest := flags.String("root-digest", "", "accepted root SHA-256 digest")
	if parseExact(flags, arguments) != nil || *path == "" || *storeBase == "" || *rootDigest == "" {
		return 2
	}
	var plan lab.SandboxPlan
	if err := decodeFile(*path, &plan); err != nil {
		return writeDenied(stdout, err)
	}
	root, err := lab.LoadAcceptedRoot(*storeBase, *rootDigest)
	if err != nil {
		return writeDenied(stdout, err)
	}
	spec, err := lab.BuildExecutionSpec(plan, root)
	if err != nil {
		return writeDenied(stdout, err)
	}
	digest, err := plan.Digest()
	if err != nil {
		return writeDenied(stdout, err)
	}
	return writeReady(stdout, map[string]any{"plan_digest": digest, "execution_spec": spec})
}

func runVerifyTestInventory(arguments []string, stdout, stderr io.Writer) int {
	flags := newFlags("verify-test-inventory", stderr)
	path := flags.String("file", "", "strict test inventory JSON")
	if parseExact(flags, arguments) != nil || *path == "" {
		return 2
	}
	var inventory lab.TestInventory
	if err := decodeFile(*path, &inventory); err != nil {
		return writeDenied(stdout, err)
	}
	if err := inventory.Validate(); err != nil {
		return writeDenied(stdout, err)
	}
	return writeReady(stdout, map[string]any{"counts": inventory.Counts})
}

func runCompareObservations(arguments []string, stdout, stderr io.Writer) int {
	flags := newFlags("compare-observations", stderr)
	firstPath := flags.String("first", "", "first strict Java observation JSON")
	secondPath := flags.String("second", "", "second strict Java observation JSON")
	if parseExact(flags, arguments) != nil || *firstPath == "" || *secondPath == "" {
		return 2
	}
	first, err := readObservation(*firstPath)
	if err != nil {
		return writeDenied(stdout, err)
	}
	second, err := readObservation(*secondPath)
	if err != nil {
		return writeDenied(stdout, err)
	}
	if err := lab.CompareJavaObservations(first, second); err != nil {
		return writeDenied(stdout, err)
	}
	digest, err := first.Digest()
	if err != nil {
		return writeDenied(stdout, err)
	}
	return writeReady(stdout, map[string]any{"observation_digest": digest})
}

func runSelectAutobahn(arguments []string, stdout, stderr io.Writer) int {
	flags := newFlags("select-autobahn", stderr)
	path := flags.String("registry-bundle", "", "strict digest-bound static Autobahn registry source bundle")
	if parseExact(flags, arguments) != nil || *path == "" {
		return 2
	}
	registry, err := readAutobahnRegistryBundle(*path)
	if err != nil {
		return writeDenied(stdout, err)
	}
	selection, err := lab.SelectAutobahnRegistry(registry)
	if err != nil {
		return writeDenied(stdout, err)
	}
	return writeReady(stdout, map[string]any{"selection": selection})
}

type autobahnResults struct {
	SchemaVersion string               `json:"schema_version"`
	Results       []lab.AutobahnResult `json:"results"`
}

func runVerifyAutobahn(arguments []string, stdout, stderr io.Writer) int {
	flags := newFlags("verify-autobahn", stderr)
	registryPath := flags.String("registry-bundle", "", "strict digest-bound static Autobahn registry source bundle")
	selectionPath := flags.String("selection", "", "strict Autobahn selection JSON")
	resultsPath := flags.String("results", "", "strict Autobahn results JSON")
	mode := flags.String("mode", "", "client or server")
	if parseExact(flags, arguments) != nil || *registryPath == "" || *selectionPath == "" || *resultsPath == "" || *mode == "" {
		return 2
	}
	registry, err := readAutobahnRegistryBundle(*registryPath)
	if err != nil {
		return writeDenied(stdout, err)
	}
	var selection lab.AutobahnSelection
	if err := decodeFile(*selectionPath, &selection); err != nil {
		return writeDenied(stdout, err)
	}
	var envelope autobahnResults
	if err := decodeFile(*resultsPath, &envelope); err != nil {
		return writeDenied(stdout, err)
	}
	if envelope.SchemaVersion != "1.0.0" {
		return writeDenied(stdout, &intake.Finding{Code: "INVALID_AUTOBAHN_RESULTS", Path: "$.schema_version", Message: "results schema must be 1.0.0"})
	}
	if err := lab.ReconcileAutobahn(registry, selection, *mode, envelope.Results); err != nil {
		return writeDenied(stdout, err)
	}
	return writeReady(stdout, map[string]any{"mode": *mode, "executed": len(envelope.Results)})
}

type autobahnRegistryBundle struct {
	SchemaVersion string                    `json:"schema_version"`
	SourceDigest  string                    `json:"source_digest"`
	SourceBase64  string                    `json:"source_base64"`
	Expansions    []autobahnExpansionSource `json:"expansions"`
}

type autobahnExpansionSource struct {
	Name         string   `json:"name"`
	SourceDigest string   `json:"source_digest"`
	SourceBase64 string   `json:"source_base64"`
	CaseIDs      []string `json:"case_ids"`
}

func readAutobahnRegistryBundle(path string) (lab.AutobahnRegistry, error) {
	var bundle autobahnRegistryBundle
	if err := decodeFile(path, &bundle); err != nil {
		return lab.AutobahnRegistry{}, err
	}
	if bundle.SchemaVersion != "1.0.0" {
		return lab.AutobahnRegistry{}, &intake.Finding{Code: "INVALID_AUTOBAHN_REGISTRY_SOURCE", Path: "$.schema_version", Message: "registry bundle schema must be 1.0.0"}
	}
	source, err := decodeCanonicalBase64(bundle.SourceBase64)
	if err != nil {
		return lab.AutobahnRegistry{}, &intake.Finding{Code: "INVALID_AUTOBAHN_REGISTRY_SOURCE", Path: "$.source_base64", Message: err.Error()}
	}
	expansions := make(map[string]lab.RegistryExpansion, len(bundle.Expansions))
	for index, item := range bundle.Expansions {
		if _, duplicate := expansions[item.Name]; duplicate || item.Name == "" {
			return lab.AutobahnRegistry{}, &intake.Finding{Code: "DUPLICATE_ENTRY", Path: fmt.Sprintf("$.expansions[%d].name", index), Message: "expansion name is empty or duplicated"}
		}
		bytes, err := decodeCanonicalBase64(item.SourceBase64)
		if err != nil {
			return lab.AutobahnRegistry{}, &intake.Finding{Code: "INVALID_AUTOBAHN_EXPANSION", Path: fmt.Sprintf("$.expansions[%d].source_base64", index), Message: err.Error()}
		}
		expansions[item.Name] = lab.RegistryExpansion{SourceDigest: item.SourceDigest, Source: bytes, CaseIDs: item.CaseIDs}
	}
	return lab.ParsePinnedAutobahnRegistry(source, bundle.SourceDigest, expansions)
}

func decodeCanonicalBase64(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) == 0 || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("source must be nonempty canonical base64")
	}
	return decoded, nil
}

type observedDisagreements struct {
	SchemaVersion string                     `json:"schema_version"`
	Observed      []lab.ObservedDisagreement `json:"observed"`
}

func runVerifyLedger(arguments []string, stdout, stderr io.Writer) int {
	flags := newFlags("verify-ledger", stderr)
	directory := flags.String("ledger-dir", "", "absolute private behavior ledger directory")
	observedPath := flags.String("observed", "", "strict observed disagreement JSON")
	if parseExact(flags, arguments) != nil || *directory == "" || *observedPath == "" {
		return 2
	}
	var observed observedDisagreements
	if err := decodeFile(*observedPath, &observed); err != nil {
		return writeDenied(stdout, err)
	}
	if observed.SchemaVersion != "1.0.0" {
		return writeDenied(stdout, &intake.Finding{Code: "INVALID_BEHAVIOR_DELTA", Path: "$.schema_version", Message: "observations schema must be 1.0.0"})
	}
	records, head, err := lab.ReadBehaviorLedger(*directory)
	if err != nil {
		return writeDenied(stdout, err)
	}
	if err := lab.DetectUnledgeredDisagreements(records, observed.Observed); err != nil {
		return writeDenied(stdout, err)
	}
	return writeReady(stdout, map[string]any{"head": head, "record_count": len(records)})
}

func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	return flags
}

func parseExact(flags *flag.FlagSet, arguments []string) error {
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	return nil
}

func readObservation(path string) (lab.OracleObservation, error) {
	data, err := readRegular(path, maxInputBytes)
	if err != nil {
		return lab.OracleObservation{}, err
	}
	return lab.DecodeOracleObservation(data)
}

func decodeFile(path string, target any) error {
	data, err := readRegular(path, maxInputBytes)
	if err != nil {
		return err
	}
	return intake.DecodeStrict(data, target)
}

func readRegular(path string, maximum int64) ([]byte, error) {
	clean := filepath.Clean(path)
	if clean != path {
		return nil, &intake.Finding{Code: "INVALID_PATH", Path: path, Message: "input path must be clean"}
	}
	before, err := os.Lstat(clean)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() < 0 || before.Size() > maximum || fileLinks(before) != 1 {
		return nil, &intake.Finding{Code: "UNSAFE_FILE", Path: path, Message: "input must be one bounded non-linked regular file"}
	}
	file, err := os.Open(clean)
	if err != nil {
		return nil, &intake.Finding{Code: "UNSAFE_FILE", Path: path, Message: "input cannot be opened"}
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || fileLinks(opened) != 1 {
		return nil, &intake.Finding{Code: "CONCURRENT_FILE_DRIFT", Path: path, Message: "input changed while opening"}
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return nil, &intake.Finding{Code: "INPUT_TOO_LARGE", Path: path, Message: "input exceeds its byte bound"}
	}
	after, err := os.Lstat(clean)
	if err != nil || !os.SameFile(opened, after) || after.Size() != int64(len(data)) || fileLinks(after) != 1 {
		return nil, &intake.Finding{Code: "CONCURRENT_FILE_DRIFT", Path: path, Message: "input changed while reading"}
	}
	return data, nil
}

func fileLinks(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Nlink)
	}
	return 1
}

func writeDenied(stdout io.Writer, err error) int {
	_ = writeJSON(stdout, map[string]any{"status": "DENIED", "finding": err})
	return 1
}

func writeReady(stdout io.Writer, result any) int {
	if err := writeJSON(stdout, map[string]any{"status": "READY", "result": result}); err != nil {
		return 1
	}
	return 0
}

func writeJSON(output io.Writer, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
