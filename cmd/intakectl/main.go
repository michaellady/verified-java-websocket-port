package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "verify" {
		fmt.Fprintln(os.Stderr, "usage: intakectl verify --evidence-dir DIR")
		os.Exit(2)
	}
	flags := flag.NewFlagSet("verify", flag.ExitOnError)
	directory := flags.String("evidence-dir", "evidence/intake", "directory containing the five intake evidence files")
	_ = flags.Parse(os.Args[2:])
	report, err := intake.VerifyEvidenceDir(*directory, time.Now().UTC())
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err != nil {
		_ = encoder.Encode(map[string]any{"status": "DENIED", "finding": err})
		os.Exit(1)
	}
	status := "READY"
	if len(report.Blockers) != 0 {
		status = "BLOCKED"
	}
	_ = encoder.Encode(map[string]any{"status": status, "report": report})
	if status != "READY" {
		os.Exit(1)
	}
}
