// Command campaignctl verifies the committed US-021 campaign evidence.
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/michaellady/verified-java-websocket-port/internal/campaign"
)

const usage = "usage: campaignctl verify --repository-root ABS\n       campaignctl corpus --repository-root ABS --seed-roots REL[,REL...]\n"

var verify = campaign.Verify
var corpusIdentity = campaign.CorpusIdentity

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 5 && arguments[0] == "corpus" && arguments[1] == "--repository-root" && arguments[3] == "--seed-roots" && filepath.IsAbs(arguments[2]) && filepath.Clean(arguments[2]) == arguments[2] {
		roots := strings.Split(arguments[4], ",")
		digest, count, err := corpusIdentity(arguments[2], roots)
		if err != nil {
			fmt.Fprintf(stderr, "corpus identity failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "%s %d\n", digest, count)
		return 0
	}
	if len(arguments) != 3 || arguments[0] != "verify" || arguments[1] != "--repository-root" || !filepath.IsAbs(arguments[2]) || filepath.Clean(arguments[2]) != arguments[2] {
		fmt.Fprint(stderr, usage)
		return 64
	}
	if err := verify(arguments[2]); err != nil {
		fmt.Fprintf(stderr, "campaign verify failed: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "PASS")
	return 0
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
