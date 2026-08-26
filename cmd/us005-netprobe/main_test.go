package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func failingDialer(network, address string, timeout time.Duration) error {
	return errors.New("connect: network is unreachable")
}

func openDialer(network, address string, timeout time.Duration) error {
	return nil
}

func selectiveDialer(network, address string, timeout time.Duration) error {
	if address == "8.8.8.8:53" {
		return nil
	}
	return errors.New("connect: operation timed out")
}

func TestProbeAllDeniedReportsNetworkDenied(t *testing.T) {
	verdict := probe(failingDialer, defaultAttempts(), time.Second)
	if !verdict.NetworkDenied {
		t.Fatalf("all dials failed but network_denied is false")
	}
	if len(verdict.Attempts) != len(defaultAttempts()) {
		t.Fatalf("expected %d attempt records, got %d",
			len(defaultAttempts()), len(verdict.Attempts))
	}
	for _, attempt := range verdict.Attempts {
		if attempt.Outcome != "denied" {
			t.Fatalf("attempt %s outcome %q, expected denied",
				attempt.Target, attempt.Outcome)
		}
		if attempt.Detail == "" {
			t.Fatalf("attempt %s lacks the denial detail", attempt.Target)
		}
	}
}

func TestProbeAnySuccessReportsNetworkOpen(t *testing.T) {
	verdict := probe(selectiveDialer, defaultAttempts(), time.Second)
	if verdict.NetworkDenied {
		t.Fatalf("a dial succeeded but network_denied is true")
	}
	open := 0
	for _, attempt := range verdict.Attempts {
		if attempt.Outcome == "connected" {
			open++
		}
	}
	if open != 1 {
		t.Fatalf("expected exactly 1 connected attempt, got %d", open)
	}
}

func TestProbeFullyOpenNetwork(t *testing.T) {
	verdict := probe(openDialer, defaultAttempts(), time.Second)
	if verdict.NetworkDenied {
		t.Fatalf("every dial succeeded but network_denied is true")
	}
}

func TestVerdictRendersDeterministicJSON(t *testing.T) {
	verdict := probe(failingDialer, defaultAttempts(), time.Second)
	rendered, err := renderVerdict(verdict)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(rendered, &parsed); err != nil {
		t.Fatalf("verdict is not valid JSON: %v", err)
	}
	for _, key := range []string{
		"assurance", "attempts", "independent_review_claimed",
		"network_denied", "probe", "schema_version"} {
		if _, present := parsed[key]; !present {
			t.Fatalf("verdict lacks %q", key)
		}
	}
	if parsed["probe"] != "us005-sealed-network-denial" {
		t.Fatalf("probe identity %v", parsed["probe"])
	}
	if parsed["assurance"] != "OWNER_ATTESTED_NOT_INDEPENDENT" {
		t.Fatalf("assurance label %v", parsed["assurance"])
	}
	if parsed["independent_review_claimed"] != false {
		t.Fatalf("independent_review_claimed must be false")
	}
}

func TestDefaultAttemptsCoverDirectIPAndDNS(t *testing.T) {
	attempts := defaultAttempts()
	if len(attempts) < 3 {
		t.Fatalf("expected at least 3 attempts, got %d", len(attempts))
	}
	sawDNSName := false
	for _, attempt := range attempts {
		if attempt.Network != "tcp" {
			t.Fatalf("unexpected network %q", attempt.Network)
		}
		host := attempt.Target[:strings.LastIndex(attempt.Target, ":")]
		if host != "" && !strings.ContainsAny(host, "0123456789.") {
			sawDNSName = true
		}
		if strings.Contains(host, "example.com") {
			sawDNSName = true
		}
	}
	if !sawDNSName {
		t.Fatalf("attempts must include a DNS-resolved target to probe name resolution")
	}
}
