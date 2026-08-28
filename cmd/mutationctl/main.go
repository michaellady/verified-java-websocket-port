// Command mutationctl executes and verifies the US-022 planted mutation campaign.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/michaellady/verified-java-websocket-port/internal/mutation"
)

const usage = "usage: mutationctl run-planted --repository-root ABS --scratch-root ABS --java ABS --maven ABS --maven-repository ABS --cargo ABS --rustc ABS\n       mutationctl verify --repository-root ABS\n"

var verify = mutation.Verify
var runPlanted = mutation.RunPlanted

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 3 && arguments[0] == "verify" && arguments[1] == "--repository-root" && cleanAbsolute(arguments[2]) {
		if err := verify(arguments[2]); err != nil {
			fmt.Fprintf(stderr, "mutation verify failed: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, "PASS")
		return 0
	}
	if len(arguments) == 15 && arguments[0] == "run-planted" && arguments[1] == "--repository-root" && arguments[3] == "--scratch-root" && arguments[5] == "--java" && arguments[7] == "--maven" && arguments[9] == "--maven-repository" && arguments[11] == "--cargo" && arguments[13] == "--rustc" {
		for _, index := range []int{2, 4, 6, 8, 10, 12, 14} {
			if !cleanAbsolute(arguments[index]) {
				fmt.Fprint(stderr, usage)
				return 64
			}
		}
		cfg := mutation.Config{RepositoryRoot: arguments[2], ScratchRoot: arguments[4], JavaExecutable: arguments[6], MavenExecutable: arguments[8], MavenRepository: arguments[10], CargoExecutable: arguments[12], RustcExecutable: arguments[14]}
		if err := runPlanted(context.Background(), cfg); err != nil {
			fmt.Fprintf(stderr, "mutation run failed: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, "PASS")
		return 0
	}
	fmt.Fprint(stderr, usage)
	return 64
}

func cleanAbsolute(path string) bool { return filepath.IsAbs(path) && filepath.Clean(path) == path }

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
