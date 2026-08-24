package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestFixedContractHasNoArbitraryExecutableOrConfiguration(t *testing.T) {
	for _, role := range []string{"fuzzingclient", "fuzzingserver"} {
		contract, err := fixedContract(role)
		if err != nil || contract.role != role || len(contract.arguments) != 4 || contract.arguments[1] != role || contract.arguments[3] != contract.configPath {
			t.Fatalf("invalid fixed contract for %s: %#v %v", role, contract, err)
		}
	}
	for _, role := range []string{"", "client", "fuzzingclient;sh", "fuzzingserver\n"} {
		if _, err := fixedContract(role); err == nil {
			t.Fatalf("accepted arbitrary role %q", role)
		}
	}
}

func TestCopySignalIsExactAndSingleUse(t *testing.T) {
	token := strings.Repeat("a", 64)
	if err := readCopySignal(strings.NewReader(token+"\n"), token); err != nil {
		t.Fatal(err)
	}
	for _, hostile := range []string{token, token + "\nextra", strings.Repeat("b", 64) + "\n", ""} {
		if err := readCopySignal(strings.NewReader(hostile), token); err == nil {
			t.Fatalf("accepted hostile signal %q", hostile)
		}
	}
}

func TestChildOutputIsBoundedAndDigestBound(t *testing.T) {
	var destination bytes.Buffer
	writer := newBoundedDigestWriter(&destination, 4)
	if written, err := writer.Write([]byte("test")); err != nil || written != 4 {
		t.Fatalf("bounded write = %d, %v", written, err)
	}
	if _, err := writer.Write([]byte("x")); err == nil {
		t.Fatal("accepted output beyond bound")
	}
	digest, count := writer.receipt()
	if digest != "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" || count != 4 || destination.String() != "test" {
		t.Fatalf("receipt = %s/%d output=%q", digest, count, destination.String())
	}
}
