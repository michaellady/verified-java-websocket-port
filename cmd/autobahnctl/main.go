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
	if len(arguments) == 0 || arguments[0] != "run" {
		fmt.Fprintln(stderr, "usage: autobahnctl run --accepted-root SHA256 --plan-digest SHA256 --archive FILE --source FILE --jdk-home DIR --runtime FILE --closure DIR --relay-source FILE --runner-source FILE --go-root DIR --work DIR --output FILE")
		return 2
	}
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

func writeFinding(output io.Writer, err error) int {
	finding := &intake.Finding{Code: "AUTOBAHN_CONTROLLER_FAILED", Path: "$", Message: err.Error()}
	if typed, ok := err.(*intake.Finding); ok {
		finding = typed
	}
	_ = json.NewEncoder(output).Encode(map[string]any{"status": "BLOCKED", "finding": finding})
	return 1
}
