package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

var environmentNamePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, time.Now().UTC()))
}

func run(arguments []string, stdout, stderr io.Writer, now time.Time) int {
	if len(arguments) == 0 {
		printUsage(stderr)
		return 2
	}
	switch arguments[0] {
	case "verify":
		return runVerify(arguments[1:], stdout, stderr, now)
	case "sign-owner-actions":
		return runSignOwnerActions(arguments[1:], stdout, stderr)
	case "promote-owner-inputs":
		return runPromoteOwnerInputs(arguments[1:], stdout, stderr, now)
	default:
		printUsage(stderr)
		return 2
	}
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage:")
	fmt.Fprintln(output, "  intakectl verify --evidence-dir DIR")
	fmt.Fprintln(output, "  intakectl sign-owner-actions --request FILE (--private-key-file FILE | --private-key-env NAME)")
	fmt.Fprintln(output, "  intakectl promote-owner-inputs --evidence-dir DIR --authority-file FILE --signed-actions-file FILE --materialization-manifest FILE --materialization-root DIR --nonce-ledger DIR --promotion-store DIR")
}

func runVerify(arguments []string, stdout, stderr io.Writer, now time.Time) int {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("evidence-dir", "evidence/intake", "directory containing the five intake evidence files")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return 2
	}
	report, err := intake.VerifyEvidenceDir(*directory, now)
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err != nil {
		_ = encoder.Encode(map[string]any{"status": "DENIED", "finding": err})
		return 1
	}
	status := "READY"
	if len(report.Blockers) != 0 {
		status = "BLOCKED"
	}
	_ = encoder.Encode(map[string]any{"status": status, "report": report})
	if status != "READY" {
		return 1
	}
	return 0
}

func runSignOwnerActions(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sign-owner-actions", flag.ContinueOnError)
	flags.SetOutput(stderr)
	requestPath := flags.String("request", "", "public owner-action request JSON")
	privateKeyPath := flags.String("private-key-file", "", "owner-only file containing a hex-encoded Ed25519 private key")
	privateKeyEnvironment := flags.String("private-key-env", "", "name of an environment variable containing the hex-encoded Ed25519 private key")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *requestPath == "" || (*privateKeyPath == "") == (*privateKeyEnvironment == "") {
		fmt.Fprintln(stderr, "sign-owner-actions requires --request and exactly one private-key source")
		return 2
	}
	requestData, err := readLimited(*requestPath, 1<<20)
	if err != nil {
		fmt.Fprintln(stderr, "cannot read owner-action request")
		return 1
	}
	var request intake.OwnerActionRequest
	if err := intake.DecodeStrict(requestData, &request); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	var privateKey ed25519.PrivateKey
	if *privateKeyPath != "" {
		privateKey, err = intake.ReadExternalPrivateKey(*privateKeyPath)
	} else {
		if !environmentNamePattern.MatchString(*privateKeyEnvironment) {
			fmt.Fprintln(stderr, "private-key environment variable name is invalid")
			return 2
		}
		value, exists := os.LookupEnv(*privateKeyEnvironment)
		_ = os.Unsetenv(*privateKeyEnvironment)
		if !exists {
			fmt.Fprintln(stderr, "private-key environment variable is absent")
			return 1
		}
		privateKey, err = intake.ParseExternalPrivateKey(value)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer clear(privateKey)
	actions, err := intake.BuildAndSignOwnerActions(request, privateKey)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(actions); err != nil {
		fmt.Fprintln(stderr, "cannot write signed actions")
		return 1
	}
	return 0
}

func runPromoteOwnerInputs(arguments []string, stdout, stderr io.Writer, now time.Time) int {
	flags := flag.NewFlagSet("promote-owner-inputs", flag.ContinueOnError)
	flags.SetOutput(stderr)
	evidenceDirectory := flags.String("evidence-dir", "", "absolute path to the five evidence files")
	authorityPath := flags.String("authority-file", "", "owner-only external authority and snapshot JSON")
	actionsPath := flags.String("signed-actions-file", "", "four signed owner actions JSON")
	manifestPath := flags.String("materialization-manifest", "", "strict 23-object materialization JSON")
	materializationRoot := flags.String("materialization-root", "", "absolute root containing materialized input bytes")
	ledgerDirectory := flags.String("nonce-ledger", "", "absolute protected durable nonce-ledger directory")
	promotionStore := flags.String("promotion-store", "", "absolute protected content-addressed promotion store")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || anyEmpty(*evidenceDirectory, *authorityPath, *actionsPath, *manifestPath, *materializationRoot, *ledgerDirectory, *promotionStore) {
		fmt.Fprintln(stderr, "promote-owner-inputs requires every protected input and storage flag")
		return 2
	}
	for _, path := range []string{*evidenceDirectory, *authorityPath, *materializationRoot, *ledgerDirectory, *promotionStore} {
		if !filepath.IsAbs(filepath.Clean(path)) {
			fmt.Fprintln(stderr, "protected promotion paths must be absolute")
			return 2
		}
	}
	if fileWithinAny(*authorityPath, *evidenceDirectory, *materializationRoot, *ledgerDirectory, *promotionStore) {
		fmt.Fprintln(stderr, "authority file must be isolated from candidate and promotion paths")
		return 1
	}
	authorityData, err := readProtectedLimited(*authorityPath, 1<<20)
	if err != nil {
		fmt.Fprintln(stderr, "cannot read protected authority file")
		return 1
	}
	actionsData, actionsErr := readLimited(*actionsPath, 2<<20)
	manifestData, manifestErr := readLimited(*manifestPath, 2<<20)
	if actionsErr != nil || manifestErr != nil {
		fmt.Fprintln(stderr, "cannot read signed actions or materialization manifest")
		return 1
	}
	var authorityDocument intake.OwnerAuthorityDocument
	var actions []intake.Action
	var manifest intake.MaterializationManifest
	if err := intake.DecodeStrict(authorityData, &authorityDocument); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := intake.DecodeStrict(actionsData, &actions); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := intake.DecodeStrict(manifestData, &manifest); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	authority, err := intake.BuildTrustedOwnerAuthority(authorityDocument, intake.FileLedger{Directory: *ledgerDirectory})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	result, err := intake.PromoteAuthorizedOwnerInputs(intake.OwnerPromotionInput{
		EvidenceDirectory: *evidenceDirectory, MaterializationRoot: *materializationRoot,
		PromotionStore: *promotionStore, Manifest: manifest, Actions: actions,
		Authority: authority, Now: now,
	})
	if err != nil {
		encoder := json.NewEncoder(stdout)
		_ = encoder.Encode(map[string]any{"status": "DENIED", "finding": err})
		return 1
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{"status": "PROMOTED", "result": result}); err != nil {
		fmt.Fprintln(stderr, "cannot write promotion result")
		return 1
	}
	return 0
}

func readLimited(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, fmt.Errorf("input exceeds limit")
	}
	return data, nil
}

func readProtectedLimited(path string, limit int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0o077 != 0 || before.Size() <= 0 || before.Size() > limit {
		return nil, fmt.Errorf("protected input is not an owner-only regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("protected input changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, fmt.Errorf("protected input exceeds limit")
	}
	return data, nil
}

func anyEmpty(values ...string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return true
		}
	}
	return false
}

func fileWithinAny(file string, roots ...string) bool {
	file = canonicalExistingPath(file)
	for _, root := range roots {
		relative, err := filepath.Rel(canonicalExistingPath(root), file)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func canonicalExistingPath(path string) string {
	cleaned := filepath.Clean(path)
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err == nil {
		return resolved
	}
	return cleaned
}
