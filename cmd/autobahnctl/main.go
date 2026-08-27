package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
	"github.com/michaellady/verified-java-websocket-port/internal/lab"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 {
		writeUsage(stderr)
		return 2
	}
	switch arguments[0] {
	case "run":
		return runQualification(arguments, stdout, stderr)
	case "prepare-rust":
		return prepareRust(arguments, stdout, stderr)
	case "verify-rust":
		return verifyRust(arguments, stdout, stderr)
	default:
		writeUsage(stderr)
		return 2
	}
}

func writeUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: autobahnctl run|prepare-rust|verify-rust [fixed flags]")
}

func runQualification(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(stderr)
	acceptedRoot := flags.String("accepted-root", "", "exact accepted root digest")
	planDigest := flags.String("plan-digest", "", "exact preflight execution plan digest")
	archive := flags.String("archive", "", "exact accepted Autobahn source archive")
	source := flags.String("source", "", "thin endpoint Java source")
	jdkHome := flags.String("jdk-home", "", "qualified JDK home")
	runtime := flags.String("runtime", "", "accepted Java-WebSocket runtime object")
	closure := flags.String("closure", "", "qualified frozen Maven closure")
	relaySource := flags.String("relay-source", "", "fixed single-session relay Go source")
	runnerSource := flags.String("runner-source", "", "fixed Autobahn supervisor Go source")
	goRoot := flags.String("go-root", "", "owner-qualified Go toolchain root")
	work := flags.String("work", "", "new private work directory")
	output := flags.String("output", "", "new receipt JSON path")
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || flags.NFlag() != 12 {
		return 2
	}
	for _, value := range []string{*acceptedRoot, *planDigest, *archive, *source, *jdkHome, *runtime, *closure, *relaySource, *runnerSource, *goRoot, *work, *output} {
		if value == "" {
			return 2
		}
	}
	if !filepath.IsAbs(*output) || filepath.Clean(*output) != *output {
		return writeFinding(stdout, &intake.Finding{Code: "INVALID_PATH", Path: "$.output", Message: "output path must be clean and absolute"})
	}
	parent := filepath.Dir(*output)
	realParent, err := filepath.EvalSymlinks(parent)
	if err != nil || realParent != parent {
		return writeFinding(stdout, &intake.Finding{Code: "INVALID_PATH", Path: "$.output", Message: "output parent must be an existing real directory"})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Hour)
	defer cancel()
	receipt, err := lab.RunAutobahnQualification(ctx, lab.AutobahnControllerConfig{
		AcceptedRootDigest: *acceptedRoot, ExpectedPlanDigest: *planDigest, ArchivePath: *archive,
		Endpoint: lab.AutobahnEndpointBuildConfig{SourcePath: *source, JDKHome: *jdkHome, RuntimePath: *runtime, ClosureDirectory: *closure, WorkDirectory: *work},
		Relay:    lab.AutobahnRelayBuildConfig{SourcePath: *relaySource, GoRoot: *goRoot, WorkDirectory: filepath.Join(*work, "relay-build")},
		Runner:   lab.AutobahnRunnerBuildConfig{SourcePath: *runnerSource, GoRoot: *goRoot, WorkDirectory: filepath.Join(*work, "runner-build")},
	})
	qualificationErr := err
	if err != nil && receipt.SchemaVersion == "" {
		return writeFinding(stdout, err)
	}
	data, marshalErr := json.MarshalIndent(receipt, "", "  ")
	if marshalErr != nil {
		return writeFinding(stdout, marshalErr)
	}
	data = append(data, '\n')
	file, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if err != nil {
		return writeFinding(stdout, err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return writeFinding(stdout, err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return writeFinding(stdout, err)
	}
	if err := file.Close(); err != nil {
		return writeFinding(stdout, err)
	}
	if qualificationErr != nil {
		fmt.Fprintf(stdout, "BLOCKED receipt=%s\n", *output)
		return writeFinding(stdout, qualificationErr)
	}
	fmt.Fprintf(stdout, "READY receipt=%s\n", *output)
	return 0
}

func prepareRust(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("prepare-rust", flag.ContinueOnError)
	flags.SetOutput(stderr)
	repositoryRoot := flags.String("repository-root", "", "real repository root")
	archive := flags.String("archive", "", "exact accepted Autobahn source archive")
	manifest := flags.String("manifest", "", "committed static case manifest")
	clientPlan := flags.String("client-plan", "", "committed inert client plan")
	serverPlan := flags.String("server-plan", "", "committed inert server plan")
	testee := flags.String("testee", "", "exact current-host Rust testee")
	us018 := flags.String("us018-evidence", "", "US-018 adapter evidence")
	baseline := flags.String("retained-baseline", "", "retained Java Autobahn baseline")
	output := flags.String("output", "", "new readiness receipt")
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || flags.NFlag() != 9 {
		return 2
	}
	for _, value := range []string{*repositoryRoot, *archive, *manifest, *clientPlan, *serverPlan, *testee, *us018, *baseline, *output} {
		if value == "" {
			return 2
		}
	}
	if err := validateNewOutput(*output); err != nil {
		return writeRustFinding(stdout, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	receipt, err := lab.PrepareRustAutobahn(ctx, lab.RustAutobahnPreparationConfig{
		RepositoryRoot: *repositoryRoot, SourceArchivePath: *archive,
		CaseManifestPath: *manifest, ClientPlanPath: *clientPlan, ServerPlanPath: *serverPlan,
		TesteePath: *testee, US018EvidencePath: *us018, RetainedBaselinePath: *baseline,
	})
	if err != nil {
		return writeRustFinding(stdout, err)
	}
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return writeRustFinding(stdout, err)
	}
	data = append(data, '\n')
	if err := writeExclusiveSynced(*output, data); err != nil {
		return writeRustFinding(stdout, err)
	}
	committed, err := os.ReadFile(*output)
	if err != nil || lab.VerifyRustAutobahnPreparation(*repositoryRoot, committed) != nil {
		return writeRustFinding(stdout, &intake.Finding{Code: "INVALID_RUST_AUTOBAHN_EVIDENCE", Path: "$.output", Message: "written receipt did not verify"})
	}
	fmt.Fprintf(stdout, "%s receipt=%s\n", lab.RustAutobahnStatus, *output)
	return 0
}

func verifyRust(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("verify-rust", flag.ContinueOnError)
	flags.SetOutput(stderr)
	repositoryRoot := flags.String("repository-root", "", "real repository root")
	evidence := flags.String("evidence", "", "readiness receipt")
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || flags.NFlag() != 2 || *repositoryRoot == "" || *evidence == "" {
		return 2
	}
	data, err := os.ReadFile(*evidence)
	if err != nil {
		return writeRustFinding(stdout, err)
	}
	if err := lab.VerifyRustAutobahnPreparation(*repositoryRoot, data); err != nil {
		return writeRustFinding(stdout, err)
	}
	fmt.Fprintf(stdout, "%s receipt=%s\n", lab.RustAutobahnStatus, *evidence)
	return 0
}

func validateNewOutput(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return &intake.Finding{Code: "INVALID_PATH", Path: "$.output", Message: "output path must be clean and absolute"}
	}
	parent := filepath.Dir(path)
	realParent, err := filepath.EvalSymlinks(parent)
	if err != nil || realParent != parent {
		return &intake.Finding{Code: "INVALID_PATH", Path: "$.output", Message: "output parent must be an existing real directory"}
	}
	return nil
}

func writeExclusiveSynced(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || written != len(data) {
		return fmt.Errorf("exclusive readiness receipt write failed")
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	syncErr = directory.Sync()
	closeErr = directory.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func writeRustFinding(output io.Writer, err error) int {
	finding := &intake.Finding{Code: "BLOCKED_STATIC_READINESS", Path: "$", Message: err.Error()}
	if typed, ok := err.(*intake.Finding); ok {
		finding = typed
	}
	_ = json.NewEncoder(output).Encode(map[string]any{"status": "BLOCKED_STATIC_READINESS", "finding": finding})
	return 1
}

func writeFinding(output io.Writer, err error) int {
	finding := &intake.Finding{Code: "AUTOBAHN_CONTROLLER_FAILED", Path: "$", Message: err.Error()}
	if typed, ok := err.(*intake.Finding); ok {
		finding = typed
	}
	_ = json.NewEncoder(output).Encode(map[string]any{"status": "BLOCKED", "finding": finding})
	return 1
}
