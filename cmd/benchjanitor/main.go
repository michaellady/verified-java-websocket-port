// benchjanitor holds the orphan-selection and destroy-loop logic for
// .github/workflows/bench-janitor.yml (review fix I6: nontrivial logic
// lives in a compiled Go binary; the workflow steps are thin
// invocations). It never provisions hosts and never produces
// measurements.
//
// Subcommands:
//
//	find    — list bench-pr-* Terraform state objects via the aws CLI
//	          and select orphans whose state is older than the age
//	          threshold. AWS listing failures fail the command loudly:
//	          masking them as "zero orphans" would green-light while a
//	          metal host bills on.
//	destroy — run the retrying terraform destroy + workspace delete
//	          loop over the selected orphan numbers; one bad workspace
//	          never aborts the batch, and any failure exits nonzero.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"

	"github.com/michaellady/verified-java-websocket-port/internal/benchexec"
	"sort"
	"strconv"
	"strings"
	"time"
)

const workspacePrefix = "bench-pr-"

var stateKeyPattern = regexp.MustCompile(`^env:/(bench-pr-([0-9]+))/benchmark/terraform\.tfstate$`)

func main() {
	runner := benchexec.ExecRunner{Stdout: os.Stdout, Stderr: os.Stderr}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, runner, time.Now, time.Sleep))
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage:")
	fmt.Fprintln(output, "  benchjanitor find --bucket BUCKET [--max-age-hours 3]")
	fmt.Fprintln(output, "  benchjanitor destroy --chdir DIR --numbers \"12 34\"")
}

func run(arguments []string, stdout, stderr io.Writer, runner benchexec.Runner, now func() time.Time, sleep func(time.Duration)) int {
	if len(arguments) == 0 {
		printUsage(stderr)
		return 2
	}
	switch arguments[0] {
	case "find":
		return runFind(arguments[1:], stdout, stderr, runner, now)
	case "destroy":
		return runDestroy(arguments[1:], stdout, stderr, runner, sleep)
	default:
		printUsage(stderr)
		return 2
	}
}

// stateObject is one S3 listing entry.
type stateObject struct {
	Key          string
	LastModified time.Time
}

// selectOrphans partitions bench-pr state objects: a workspace whose
// state was modified at or before the cutoff is an orphan (job-scoped
// stacks never legitimately outlive the job's 2-hour timeout); anything
// newer may be an in-flight benchmark job and is kept.
func selectOrphans(objects []stateObject, cutoff time.Time) (orphans []int, lines []string) {
	for _, object := range objects {
		match := stateKeyPattern.FindStringSubmatch(object.Key)
		if match == nil {
			continue
		}
		workspace := match[1]
		number, err := strconv.Atoi(match[2])
		if err != nil {
			continue
		}
		if object.LastModified.After(cutoff) {
			lines = append(lines, fmt.Sprintf("keep %s — state modified after the age cutoff (benchmark job may be in flight)", workspace))
		} else {
			lines = append(lines, fmt.Sprintf("ORPHAN %s — state untouched past the age cutoff (job-scoped lifecycle should have destroyed it)", workspace))
			orphans = append(orphans, number)
		}
	}
	sort.Ints(orphans)
	return orphans, lines
}

func runFind(arguments []string, stdout, stderr io.Writer, runner benchexec.Runner, now func() time.Time) int {
	flags := flag.NewFlagSet("find", flag.ContinueOnError)
	flags.SetOutput(stderr)
	bucket := flags.String("bucket", "", "tfstate bucket name")
	maxAgeHours := flags.Float64("max-age-hours", 3, "orphan age threshold in hours")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *bucket == "" || *maxAgeHours <= 0 {
		printUsage(stderr)
		return 2
	}

	// The listing is its own checked command: an AWS failure
	// (AccessDenied, missing bucket, expired creds) must fail the run.
	listing, err := runner.Output("aws", "s3api", "list-objects-v2",
		"--bucket", *bucket, "--prefix", "env:/"+workspacePrefix, "--output", "json")
	if err != nil {
		fmt.Fprintf(stderr, "error: aws s3api list-objects-v2 failed: %v (a listing failure must never read as zero orphans)\n", err)
		return 1
	}
	objects, err := parseListing(listing)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	cutoff := now().Add(-time.Duration(*maxAgeHours * float64(time.Hour)))
	orphans, lines := selectOrphans(objects, cutoff)
	for _, line := range lines {
		fmt.Fprintln(stdout, line)
	}
	rendered := renderNumbers(orphans)
	if rendered == "" {
		fmt.Fprintln(stdout, "Orphans: none")
	} else {
		fmt.Fprintf(stdout, "Orphans: %s\n", rendered)
	}
	if outputPath := os.Getenv("GITHUB_OUTPUT"); outputPath != "" {
		if err := appendLine(outputPath, "orphans="+rendered); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
	}
	return 0
}

// parseListing decodes the aws s3api list-objects-v2 JSON body. An
// empty body (no matching objects) is a valid empty listing.
func parseListing(listing []byte) ([]stateObject, error) {
	trimmed := strings.TrimSpace(string(listing))
	if trimmed == "" {
		return nil, nil
	}
	var document struct {
		Contents []struct {
			Key          string    `json:"Key"`
			LastModified time.Time `json:"LastModified"`
		} `json:"Contents"`
	}
	if err := json.Unmarshal([]byte(trimmed), &document); err != nil {
		return nil, fmt.Errorf("could not parse the S3 listing: %w", err)
	}
	objects := make([]stateObject, 0, len(document.Contents))
	for _, entry := range document.Contents {
		objects = append(objects, stateObject{Key: entry.Key, LastModified: entry.LastModified})
	}
	return objects, nil
}

func runDestroy(arguments []string, stdout, stderr io.Writer, runner benchexec.Runner, sleep func(time.Duration)) int {
	flags := flag.NewFlagSet("destroy", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("chdir", "", "terraform benchmark root directory")
	numbers := flags.String("numbers", "", "space-separated orphan PR numbers")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *directory == "" {
		printUsage(stderr)
		return 2
	}
	orphanNumbers, err := parseNumbers(*numbers)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	if len(orphanNumbers) == 0 {
		fmt.Fprintln(stdout, "no orphans to destroy")
		return 0
	}

	var swept, failed []string
	for _, number := range orphanNumbers {
		workspace := workspacePrefix + strconv.Itoa(number)
		fmt.Fprintf(stdout, "::group::destroy %s\n", workspace)
		if err := runner.Run(*directory, "terraform", "workspace", "select", workspace); err != nil {
			fmt.Fprintf(stdout, "could not select %s\n", workspace)
			failed = append(failed, workspace)
			fmt.Fprintln(stdout, "::endgroup::")
			continue
		}
		destroyed := false
		for attempt := 1; attempt <= 2; attempt++ {
			// allow_unpinned_ami=true here only satisfies the
			// provision-time precondition so destroy can plan; the
			// janitor never creates hosts and never produces
			// measurements.
			err := runner.Run(*directory, "terraform", "destroy", "-auto-approve", "-input=false",
				"-var", "pr_number="+strconv.Itoa(number), "-var", "allow_unpinned_ami=true")
			if err == nil {
				destroyed = true
				break
			}
			fmt.Fprintf(stdout, "destroy attempt %d failed for %s", attempt, workspace)
			if attempt < 2 {
				fmt.Fprint(stdout, "; sleeping 60s")
				sleep(60 * time.Second)
			}
			fmt.Fprintln(stdout)
		}
		// One bad workspace must not abort the batch: guard everything
		// after the destroy so remaining orphans still get swept and
		// the summary + failure report still render.
		_ = runner.Run(*directory, "terraform", "workspace", "select", "default")
		if destroyed {
			if err := runner.Run(*directory, "terraform", "workspace", "delete", workspace); err != nil {
				fmt.Fprintf(stdout, "destroyed %s but workspace delete failed — retained for inspection\n", workspace)
				failed = append(failed, workspace)
			} else {
				fmt.Fprintf(stdout, "cleaned %s\n", workspace)
				swept = append(swept, workspace)
			}
		} else {
			failed = append(failed, workspace)
		}
		fmt.Fprintln(stdout, "::endgroup::")
	}

	summary := fmt.Sprintf("## Bench workspace janitor\n- swept: %s\n- failed: %s\n",
		orNone(strings.Join(swept, " ")), orNone(strings.Join(failed, " ")))
	if summaryPath := os.Getenv("GITHUB_STEP_SUMMARY"); summaryPath != "" {
		if err := appendLine(summaryPath, summary); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
	} else {
		fmt.Fprint(stdout, summary)
	}
	if len(failed) > 0 {
		fmt.Fprintf(stdout, "::error::janitor could not destroy: %s — a metal host may STILL be billing; investigate immediately (next 3h run retries).\n", strings.Join(failed, " "))
		return 1
	}
	return 0
}

func parseNumbers(value string) ([]int, error) {
	var numbers []int
	for _, field := range strings.Fields(value) {
		number, err := strconv.Atoi(field)
		if err != nil || number < 0 {
			return nil, fmt.Errorf("orphan number %q is not a non-negative decimal", field)
		}
		numbers = append(numbers, number)
	}
	return numbers, nil
}

func renderNumbers(numbers []int) string {
	fields := make([]string, len(numbers))
	for i, number := range numbers {
		fields[i] = strconv.Itoa(number)
	}
	return strings.Join(fields, " ")
}

func orNone(value string) string {
	if strings.TrimSpace(value) == "" {
		return "none"
	}
	return value
}

func appendLine(path, line string) error {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.WriteString(line + "\n")
	return err
}
