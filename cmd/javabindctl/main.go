// Command javabindctl produces and verifies the Java formal-binding evidence
// for the immutable 24-obligation catalog.
//
//	javabindctl observe -repo . -java ... -javac ... -jar-tool ... \
//	    -runtime-jar ... -slf4j ... -java-source-root ... -work ...
//	javabindctl verify  -repo .
//
// "observe" executes the pinned Java runtime and rewrites the receipt and the
// derived coverage projection. "verify" recomputes the projection from the
// retained artifacts alone and fails when the stored projection disagrees with
// what the evidence derives.
//
// Nothing here proves anything about the Java library; see
// docs/java-formal-binding-design.md.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/michaellady/verified-java-websocket-port/internal/javabind"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "javabindctl:", err)
		os.Exit(1)
	}
}

func run(args []string, out *os.File) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: javabindctl <observe|verify> [flags]")
	}
	switch args[0] {
	case "observe":
		return runObserve(args[1:], out)
	case "verify":
		return runVerify(args[1:], out)
	default:
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func runObserve(args []string, out *os.File) error {
	flags := flag.NewFlagSet("observe", flag.ContinueOnError)
	repo := flags.String("repo", "", "repository root")
	java := flags.String("java", "", "absolute path to the promoted java executable")
	javac := flags.String("javac", "", "absolute path to the promoted javac executable")
	jarTool := flags.String("jar-tool", "", "absolute path to the promoted jar executable")
	runtimeJAR := flags.String("runtime-jar", "", "absolute path to the pinned Java-WebSocket 1.6.0 jar")
	slf4j := flags.String("slf4j", "", "absolute path to the pinned SLF4J API jar")
	sourceRoot := flags.String("java-source-root", "", "absolute path to the quarantined src/main/java root")
	work := flags.String("work", "", "absolute path to a writable working directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	root, err := filepath.Abs(*repo)
	if err != nil {
		return err
	}
	config := javabind.ObserveConfig{
		RepoRoot:       root,
		Java:           *java,
		Javac:          *javac,
		JarTool:        *jarTool,
		RuntimeJAR:     *runtimeJAR,
		SLF4JAPI:       *slf4j,
		JavaSourceRoot: *sourceRoot,
		WorkDir:        *work,
	}
	receipt, _, _, err := javabind.Observe(context.Background(), config)
	if err != nil {
		return err
	}
	encoded, err := javabind.MarshalArtifact(receipt)
	if err != nil {
		return err
	}
	receiptPath := filepath.Join(root, filepath.FromSlash(javabind.ReceiptPath))
	if err := os.MkdirAll(filepath.Dir(receiptPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(receiptPath, encoded, 0o644); err != nil {
		return err
	}
	projection, err := javabind.Verify(root)
	if err != nil {
		return err
	}
	projectionEncoded, err := javabind.MarshalArtifact(projection)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(javabind.ProjectionPath)), projectionEncoded, 0o644); err != nil {
		return err
	}
	report(out, projection)
	return nil
}

func runVerify(args []string, out *os.File) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	repo := flags.String("repo", "", "repository root")
	if err := flags.Parse(args); err != nil {
		return err
	}
	root, err := filepath.Abs(*repo)
	if err != nil {
		return err
	}
	projection, err := javabind.Verify(root)
	if err != nil {
		return err
	}
	derived, err := javabind.MarshalArtifact(projection)
	if err != nil {
		return err
	}
	stored, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(javabind.ProjectionPath)))
	if err != nil {
		return err
	}
	if !bytes.Equal(bytes.TrimRight(stored, "\n"), bytes.TrimRight(derived, "\n")) {
		// Print what the evidence actually derives before failing, so the operator
		// sees the honest numbers rather than only that the file disagreed.
		fmt.Fprintln(out, "DERIVED FROM THE RETAINED EVIDENCE (the stored projection disagrees):")
		report(out, projection)
		return fmt.Errorf("the retained coverage projection is not what the retained evidence derives")
	}
	report(out, projection)
	return nil
}

func report(out *os.File, projection javabind.Projection) {
	counts := projection.Counts
	fmt.Fprintf(out, "catalog=%s denominator=%d\n", projection.CatalogID, counts.Denominator)
	fmt.Fprintf(out, "java_bindings_connected=%d/%d\n", counts.JavaBindingsConnected, counts.Denominator)
	fmt.Fprintf(out, "java_bindings_partial=%d/%d\n", counts.JavaBindingsPartial, counts.Denominator)
	fmt.Fprintf(out, "java_bindings_disconnected=%d/%d\n", counts.JavaBindingsDisconnected, counts.Denominator)
	fmt.Fprintf(out, "java_mutation_sensitive=%d/%d\n", counts.JavaMutationSensitive, counts.Denominator)
	fmt.Fprintf(out, "java_bindings_at_required_strength=%d/%d\n", counts.JavaBindingsAtRequiredStrength, counts.Denominator)
	fmt.Fprintf(out, "refinement=%d/%d\n", counts.Refinement, counts.Denominator)
	fmt.Fprintf(out, "aggregate=%d/%d\n", counts.Aggregate, counts.Denominator)
	fmt.Fprintf(out, "observed_strength=%s required_strength=%s\n", projection.ObservedStrength, projection.RequiredStrength)
	fmt.Fprintf(out, "assurance=%s independent_review_claimed=%t\n", projection.Assurance.Assurance, projection.Assurance.IndependentReviewClaim)
}
