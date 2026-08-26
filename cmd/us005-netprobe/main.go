// Command us005-netprobe is the US-005 sealed-network denial probe workload.
// It runs INSIDE the accepted US-007 Docker sbx workload profile during
// sealed-tier candidate execution and attempts outbound TCP connections
// (direct-IP and DNS-resolved). Under the profile's default-deny network
// policy every attempt must fail; the probe prints a JSON verdict on stdout
// and exits 0 only when the network is fully denied. On an open network it
// exits 1 — running it on the host first is the self-test that proves the
// probe actually detects openness.
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

const probeTimeout = 5 * time.Second

// Attempt is one outbound connectivity attempt specification.
type Attempt struct {
	Network string `json:"network"`
	Target  string `json:"target"`
}

// AttemptResult records one attempt's observed outcome.
type AttemptResult struct {
	Network string `json:"network"`
	Target  string `json:"target"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail"`
}

// Verdict is the probe's machine-readable result document.
type Verdict struct {
	SchemaVersion            string          `json:"schema_version"`
	Probe                    string          `json:"probe"`
	Attempts                 []AttemptResult `json:"attempts"`
	NetworkDenied            bool            `json:"network_denied"`
	Assurance                string          `json:"assurance"`
	IndependentReviewClaimed bool            `json:"independent_review_claimed"`
}

// defaultAttempts probes a direct IPv4 HTTPS endpoint, a direct IPv4 DNS
// endpoint, and a DNS-resolved name, so both raw egress and name resolution
// are exercised.
func defaultAttempts() []Attempt {
	return []Attempt{
		{Network: "tcp", Target: "1.1.1.1:443"},
		{Network: "tcp", Target: "8.8.8.8:53"},
		{Network: "tcp", Target: "example.com:443"},
	}
}

type dialer func(network, address string, timeout time.Duration) error

func netDialer(network, address string, timeout time.Duration) error {
	connection, err := net.DialTimeout(network, address, timeout)
	if err != nil {
		return err
	}
	return connection.Close()
}

func probe(dial dialer, attempts []Attempt, timeout time.Duration) Verdict {
	verdict := Verdict{
		SchemaVersion:            "1.0.0",
		Probe:                    "us005-sealed-network-denial",
		NetworkDenied:            true,
		Assurance:                "OWNER_ATTESTED_NOT_INDEPENDENT",
		IndependentReviewClaimed: false,
	}
	for _, attempt := range attempts {
		result := AttemptResult{Network: attempt.Network, Target: attempt.Target}
		if err := dial(attempt.Network, attempt.Target, timeout); err != nil {
			result.Outcome = "denied"
			result.Detail = err.Error()
		} else {
			result.Outcome = "connected"
			result.Detail = "outbound connection succeeded"
			verdict.NetworkDenied = false
		}
		verdict.Attempts = append(verdict.Attempts, result)
	}
	return verdict
}

func renderVerdict(verdict Verdict) ([]byte, error) {
	return json.MarshalIndent(verdict, "", "  ")
}

func main() {
	for _, argument := range os.Args[1:] {
		if argument == "--identify" {
			fmt.Println(`{"artifact":"us005-netprobe",` +
				`"purpose":"us005-sealed-network-denial","version":"1.0.0"}`)
			return
		}
	}
	verdict := probe(netDialer, defaultAttempts(), probeTimeout)
	rendered, err := renderVerdict(verdict)
	if err != nil {
		fmt.Fprintln(os.Stderr, "us005-netprobe:", err)
		os.Exit(2)
	}
	fmt.Println(string(rendered))
	if !verdict.NetworkDenied {
		os.Exit(1)
	}
}
