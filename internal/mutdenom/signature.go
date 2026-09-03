package mutdenom

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
)

// verifySignature checks an Ed25519 signature over the canonical payload digest
// string. The digest, not the document, is signed, so the verifier and the
// digest check agree by construction: if the document drifts the digest moves,
// and the signature stops verifying.
//
// This function is deliberately total and quiet -- a malformed key, a malformed
// signature, and a wrong signature are all simply "does not verify". There is no
// path through it that treats an unverifiable signature as an acceptable one.
func verifySignature(publicKey []byte, payloadDigest, signatureHex string) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	signature, err := hex.DecodeString(strings.TrimSpace(signatureHex))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(publicKey), []byte(payloadDigest), signature)
}
