package corpora

import (
	"crypto/sha256"
	"encoding/binary"
	"unicode/utf8"
)

// Stream is a SHA-256 counter-mode deterministic byte stream keyed by
// (seed, label). It uses no Go runtime randomness: every draw is re-derivable
// from the two strings by any SHA-256 implementation in any language.
type Stream struct {
	key     [32]byte
	counter uint64
	buffer  []byte
}

// NewStream derives an independent stream for one seed and label.
func NewStream(seed, label string) *Stream {
	h := sha256.New()
	h.Write([]byte("us005-corpora-stream-v1\x00"))
	h.Write([]byte(seed))
	h.Write([]byte{0x00})
	h.Write([]byte(label))
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return &Stream{key: key}
}

func (s *Stream) refill() {
	var block [40]byte
	copy(block[:32], s.key[:])
	binary.BigEndian.PutUint64(block[32:], s.counter)
	s.counter++
	sum := sha256.Sum256(block[:])
	s.buffer = append(s.buffer, sum[:]...)
}

// Bytes returns the next n stream bytes.
func (s *Stream) Bytes(n int) []byte {
	for len(s.buffer) < n {
		s.refill()
	}
	out := make([]byte, n)
	copy(out, s.buffer[:n])
	s.buffer = s.buffer[n:]
	return out
}

// Byte returns one stream byte.
func (s *Stream) Byte() byte {
	return s.Bytes(1)[0]
}

// Intn returns a uniform value in [0, n) by rejection sampling.
func (s *Stream) Intn(n int) int {
	if n <= 0 {
		panic("Intn requires n > 0")
	}
	bound := uint64(n)
	limit := (^uint64(0) / bound) * bound
	for {
		raw := binary.BigEndian.Uint64(s.Bytes(8))
		if raw < limit {
			return int(raw % bound)
		}
	}
}

// Mask returns a 4-byte masking key.
func (s *Stream) Mask() [4]byte {
	var mask [4]byte
	copy(mask[:], s.Bytes(4))
	return mask
}

// ASCII returns n printable ASCII characters (0x20..0x7e).
func (s *Stream) ASCII(n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(0x20 + s.Intn(0x5f))
	}
	return string(out)
}

// UTF8Text returns valid UTF-8 text of exactly n runes drawn from a small
// multilingual alphabet, so fragment boundaries can be placed between runes.
func (s *Stream) UTF8Text(runes int) string {
	alphabet := []rune("abcdefghijklmnopqrstuvwxyz0123456789 äöüßéèñ漢字仮名한글")
	out := make([]rune, runes)
	for i := range out {
		out[i] = alphabet[s.Intn(len(alphabet))]
	}
	text := string(out)
	if !utf8.ValidString(text) {
		panic("UTF8Text produced invalid UTF-8")
	}
	return text
}
