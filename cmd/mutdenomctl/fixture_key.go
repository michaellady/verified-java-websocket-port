package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/michaellady/verified-java-websocket-port/internal/mutdenom"
)

// FixtureKeySeedPhrase derives the polarity suite's signing key. It is written
// here in the open ON PURPOSE.
//
// A polarity suite needs one manifest that verifies end to end, or a checker
// that blocked unconditionally would pass its own tests. That manifest has to
// carry a real Ed25519 signature over its real payload digest. Committing a
// private key to do that would put a usable secret in the repository, so
// instead the fixture key is DERIVED from this published phrase: anyone can
// regenerate it, nobody can mistake it for a secret, and a signature made with
// it proves only that the verifier works.
//
// The real denominator is signed by the protected operator with key material
// this repository never holds (internal/intake/sign.go takes the private key as
// an argument). SignFixture below refuses to touch any document whose id is not
// a polarity fixture, so this key cannot be used to sign the real one.
const FixtureKeySeedPhrase = "us022-mutdenom-polarity-fixture-key-v1 NOT-A-SECRET"

// FixtureDocumentIDPrefix is the only document id SignFixture will sign.
const FixtureDocumentIDPrefix = "us022-polarity-fixture-"

// fixtureKey returns the derived, published, non-secret fixture keypair.
func fixtureKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := sha256.Sum256([]byte(FixtureKeySeedPhrase))
	private := ed25519.NewKeyFromSeed(seed[:])
	return private.Public().(ed25519.PublicKey), private
}

// SignFixture stamps a polarity fixture with its real payload digest and a real
// signature over it, then rewrites the file. It REFUSES any document whose id
// does not begin with FixtureDocumentIDPrefix: signing the real denominator
// with a published key would be worse than leaving it unsigned, because it
// would look signed.
func SignFixture(root, relPath string) int {
	path := filepath.Join(root, relPath)
	manifest, err := mutdenom.LoadManifest(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mutdenomctl: sign-fixture: %v\n", err)
		return 2
	}
	if !strings.HasPrefix(manifest.DocumentID, FixtureDocumentIDPrefix) {
		fmt.Fprintf(os.Stderr,
			"mutdenomctl: sign-fixture REFUSED: document_id %q does not begin with %q. "+
				"This key is published in cmd/mutdenomctl/fixture_key.go and signing a real "+
				"denominator with it would make an unsigned document look signed.\n",
			manifest.DocumentID, FixtureDocumentIDPrefix)
		return 2
	}
	public, private := fixtureKey()
	manifest.Signature.PublicKeyHex = hex.EncodeToString(public)
	manifest.Signature.KeyID = "us022-polarity-fixture-key (published, non-secret)"
	digest, err := mutdenom.PayloadDigest(manifest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mutdenomctl: sign-fixture: %v\n", err)
		return 2
	}
	manifest.Signature.PayloadDigest = digest
	manifest.Signature.Signature = hex.EncodeToString(ed25519.Sign(private, []byte(digest)))

	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "mutdenomctl: sign-fixture: %v\n", err)
		return 2
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "mutdenomctl: sign-fixture: %v\n", err)
		return 2
	}
	fmt.Printf("gate=mutdenom step=sign-fixture path=%s payload_digest=%s key=%s\n",
		relPath, digest, manifest.Signature.KeyID)
	return 0
}
