// Command resource-envelope-artifact is the reviewed, standard-library-only
// target built by the protected US-007 benign-operation descriptor.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func main() {
	sum := sha256.Sum256([]byte("verified-java-websocket-port/us007/resource-envelope-artifact/v1"))
	fmt.Println(hex.EncodeToString(sum[:]))
}
