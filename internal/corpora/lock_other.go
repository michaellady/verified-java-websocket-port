//go:build !unix

package corpora

import "fmt"

// acquireFileLock fails closed on hosts without advisory file locking: the
// custodian ledger must never be spent without mutual exclusion.
func acquireFileLock(path string) (func(), error) {
	return nil, fmt.Errorf("custodian ledger locking requires a unix host")
}
