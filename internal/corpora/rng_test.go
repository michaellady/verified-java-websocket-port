package corpora

import (
	"bytes"
	"testing"
)

// The corpus generator draws every random choice from a SHA-256 counter-mode
// stream keyed by (seed, label). The stream must be deterministic, label
// separated, and independent of Go runtime randomness so a validator in any
// language can re-derive every byte.
func TestStreamIsDeterministicPerSeedAndLabel(t *testing.T) {
	a1 := NewStream("seedA", "label1").Bytes(64)
	a2 := NewStream("seedA", "label1").Bytes(64)
	if !bytes.Equal(a1, a2) {
		t.Fatal("same seed and label must produce identical bytes")
	}
	b := NewStream("seedA", "label2").Bytes(64)
	if bytes.Equal(a1, b) {
		t.Fatal("different labels must produce different streams")
	}
	c := NewStream("seedB", "label1").Bytes(64)
	if bytes.Equal(a1, c) {
		t.Fatal("different seeds must produce different streams")
	}
}

func TestStreamIntnIsUnbiasedBoundAndDeterministic(t *testing.T) {
	s := NewStream("seed", "intn")
	for i := 0; i < 1000; i++ {
		v := s.Intn(7)
		if v < 0 || v >= 7 {
			t.Fatalf("Intn(7) out of range: %d", v)
		}
	}
	first := NewStream("seed", "intn").Intn(1 << 20)
	second := NewStream("seed", "intn").Intn(1 << 20)
	if first != second {
		t.Fatal("Intn must be deterministic for a fresh stream")
	}
}

func TestStreamASCIIAndUTF8Text(t *testing.T) {
	s := NewStream("seed", "text")
	ascii := s.ASCII(32)
	if len(ascii) != 32 {
		t.Fatalf("ASCII length = %d", len(ascii))
	}
	for _, r := range ascii {
		if r < 0x20 || r > 0x7e {
			t.Fatalf("ASCII produced non-printable rune %q", r)
		}
	}
	text := s.UTF8Text(16)
	if !bytes.Equal([]byte(text), []byte(string([]rune(string([]byte(text)))))) {
		t.Fatal("UTF8Text must produce valid UTF-8")
	}
}
