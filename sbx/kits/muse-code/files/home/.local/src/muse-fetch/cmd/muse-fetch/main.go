package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/michaellady/verified-java-websocket-port/sbx/muse-fetch/internal/fetch"
)

const downloadTimeout = 10 * time.Minute

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(arguments []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("muse-fetch", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var artifact fetch.Artifact
	flags.StringVar(&artifact.URL, "url", "", "exact artifact URL")
	flags.StringVar(&artifact.SHA256, "sha256", "", "expected SHA-256 in hexadecimal")
	flags.Int64Var(&artifact.Size, "size", -1, "expected artifact size in bytes")
	flags.StringVar(&artifact.Destination, "destination", "", "absolute destination path")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "muse-fetch: positional arguments are not accepted")
		return 2
	}
	if artifact.URL == "" || artifact.SHA256 == "" || artifact.Size < 0 || artifact.Destination == "" {
		fmt.Fprintln(stderr, "muse-fetch: --url, --sha256, --size, and --destination are required")
		return 2
	}

	downloader := fetch.Downloader{
		Client:  fetch.NewHTTPClient(downloadTimeout),
		Timeout: downloadTimeout,
	}
	if err := downloader.Fetch(context.Background(), artifact); err != nil {
		fmt.Fprintf(stderr, "muse-fetch: %v\n", err)
		return 1
	}
	return 0
}
