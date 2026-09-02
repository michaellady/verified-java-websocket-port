package javabind

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
)

// gitBlobID computes the Git object name of a blob with the given contents, so a
// vendored artifact can be checked against the object id it has in the branch it
// was read from. sha1 is used because that is the object format Git uses for
// this repository; it is an identity lookup, not a security control.
func gitBlobID(data []byte) string {
	hasher := sha1.New() //nolint:gosec // Git object identity, not a security digest
	fmt.Fprintf(hasher, "blob %d\x00", len(data))
	hasher.Write(data)
	return hex.EncodeToString(hasher.Sum(nil))
}
