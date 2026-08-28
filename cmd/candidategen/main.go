// Command candidategen materializes the monotonic US-023 content, envelope,
// external receipts, and derived reports. It is intentionally not a verifier.
package main

import (
	"fmt"
	"os"

	"github.com/michaellady/verified-java-websocket-port/internal/assurance"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) < 3 || arguments[1] != "--root" || arguments[2] == "" {
		return fmt.Errorf("usage: candidategen PHASE --root ABS [--target COMMIT] [--content COMMIT]")
	}
	phase, root := arguments[0], arguments[2]
	switch phase {
	case "content":
		if len(arguments) != 5 || arguments[3] != "--target" {
			return fmt.Errorf("content requires --target COMMIT")
		}
		return assurance.MaterializeCandidateContent(root, arguments[4])
	case "manifest":
		if len(arguments) != 7 || arguments[3] != "--target" || arguments[5] != "--content" {
			return fmt.Errorf("manifest requires --target COMMIT --content COMMIT")
		}
		return assurance.MaterializeCandidateManifest(root, arguments[4], arguments[6])
	case "receipts":
		if len(arguments) != 3 {
			return fmt.Errorf("receipts accepts only --root")
		}
		return assurance.MaterializeCandidateReceipts(root)
	case "reports":
		if len(arguments) != 3 {
			return fmt.Errorf("reports accepts only --root")
		}
		return assurance.MaterializeCandidateReports(root)
	default:
		return fmt.Errorf("unknown phase %q", phase)
	}
}
