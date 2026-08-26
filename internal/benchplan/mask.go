package benchplan

import (
	"crypto/sha256"
	"fmt"
	"strconv"
)

// MaskSpecVersion is the frozen masking-key derivation rule identifier
// (review fix B1). Every masked client frame in every workload derives
// its RFC 6455 32-bit masking key from this rule, so the full wire
// bytes of every declared frame are deterministic.
const MaskSpecVersion = "vjwp-us008-mask|v1"

// MaskingKey derives the frozen 32-bit masking key for one client
// frame. The frozen rule:
//
//	material = MaskSpecVersion + "|" + workload_id + "|" +
//	           decimal(pair_index) + "|" + decimal(frame_index)
//	key      = first 4 bytes of SHA-256(ASCII(material))
//
// pair_index is the pair (0..34, warmup and measured alike); the Java
// and Rust sample runs of the same pair send byte-identical wire
// traffic, so they share the same key sequence. frame_index is the
// 0-based index of the client-sent masked frame within one sample run,
// in send order, counting every masked frame (data, continuation, ping,
// pong, and close; the HTTP handshake is not a frame). The rule is a
// pure hash of frozen public strings: it admits no discretion and
// cannot be re-rolled after results are known.
func MaskingKey(workloadID string, pairIndex, frameIndex int) ([4]byte, error) {
	var key [4]byte
	if !isKnownWorkload(workloadID) {
		return key, fmt.Errorf("unknown workload id %q", workloadID)
	}
	if pairIndex < 0 || pairIndex >= TotalPairs {
		return key, fmt.Errorf("pair index %d outside 0..%d", pairIndex, TotalPairs-1)
	}
	if frameIndex < 0 {
		return key, fmt.Errorf("frame index %d is negative", frameIndex)
	}
	material := MaskSpecVersion + "|" + workloadID + "|" + strconv.Itoa(pairIndex) + "|" + strconv.Itoa(frameIndex)
	digest := sha256.Sum256([]byte(material))
	copy(key[:], digest[:4])
	return key, nil
}
