package benchplan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

// goldenMaskingKeys were derived with an independent Python hashlib
// implementation of the frozen masking rule, so a drift in the Go
// implementation cannot re-derive its own expectation.
var goldenMaskingKeys = []struct {
	workloadID string
	pairIndex  int
	frameIndex int
	keyHex     string
}{
	{"wl-01-handshake-close", 0, 0, "fbccc202"},
	{"wl-01-handshake-close", 0, 1, "760d0714"},
	{"wl-01-handshake-close", 34, 0, "dc5a09b3"},
	{"wl-02-small-text-echo", 5, 9999, "7fdeab75"},
	{"wl-06-concurrent-pressure", 17, 255, "fb37c634"},
}

func TestMaskingKeyMatchesIndependentGoldenVectors(t *testing.T) {
	for _, golden := range goldenMaskingKeys {
		key, err := MaskingKey(golden.workloadID, golden.pairIndex, golden.frameIndex)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(key[:]); got != golden.keyHex {
			t.Errorf("mask(%s, %d, %d) = %s, independent golden vector %s",
				golden.workloadID, golden.pairIndex, golden.frameIndex, got, golden.keyHex)
		}
	}
}

func TestMaskingKeyConformsToWrittenSpec(t *testing.T) {
	// Re-derive keys directly from the spec text, written out literally.
	for _, workloadID := range WorkloadIDs {
		for _, pairIndex := range []int{0, 4, 5, 34} {
			for _, frameIndex := range []int{0, 1, 1000} {
				material := "vjwp-us008-mask|v1|" + workloadID + "|" + fmt.Sprintf("%d", pairIndex) + "|" + fmt.Sprintf("%d", frameIndex)
				digest := sha256.Sum256([]byte(material))
				key, err := MaskingKey(workloadID, pairIndex, frameIndex)
				if err != nil {
					t.Fatal(err)
				}
				for i := 0; i < 4; i++ {
					if key[i] != digest[i] {
						t.Fatalf("mask(%s, %d, %d) byte %d disagrees with the written spec", workloadID, pairIndex, frameIndex, i)
					}
				}
			}
		}
	}
}

func TestMaskingKeyIsDeterministicAndDistinct(t *testing.T) {
	first, err := MaskingKey("wl-02-small-text-echo", 7, 3)
	if err != nil {
		t.Fatal(err)
	}
	second, err := MaskingKey("wl-02-small-text-echo", 7, 3)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("masking key not deterministic")
	}
	seen := map[[4]byte][]string{}
	for _, workloadID := range WorkloadIDs {
		for pairIndex := 0; pairIndex < 3; pairIndex++ {
			for frameIndex := 0; frameIndex < 3; frameIndex++ {
				key, err := MaskingKey(workloadID, pairIndex, frameIndex)
				if err != nil {
					t.Fatal(err)
				}
				seen[key] = append(seen[key], fmt.Sprintf("%s/%d/%d", workloadID, pairIndex, frameIndex))
			}
		}
	}
	for key, users := range seen {
		if len(users) > 1 {
			t.Errorf("masking key %x collides across %v (54 distinct inputs must not collide)", key, users)
		}
	}
}

func TestMaskingKeyRejectsInvalidInput(t *testing.T) {
	if _, err := MaskingKey("wl-99-not-preregistered", 0, 0); err == nil {
		t.Error("expected error for unknown workload")
	}
	if _, err := MaskingKey("wl-01-handshake-close", -1, 0); err == nil {
		t.Error("expected error for negative pair index")
	}
	if _, err := MaskingKey("wl-01-handshake-close", 35, 0); err == nil {
		t.Error("expected error for pair index past 34")
	}
	if _, err := MaskingKey("wl-01-handshake-close", 0, -1); err == nil {
		t.Error("expected error for negative frame index")
	}
}
