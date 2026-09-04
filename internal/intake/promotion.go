package intake

import (
	"bytes"
	"sync"
)

type MemoryStore struct {
	mu     sync.Mutex
	values map[string]Object
	failID string
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{values: make(map[string]Object)} }

func (s *MemoryStore) FailOn(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failID = id
}

func (s *MemoryStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.values)
}

func PromoteBatch(store *MemoryStore, objects []Object) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	staged := make(map[string]Object, len(objects))
	for _, object := range objects {
		if object.ID == "" || !validateDigest(object.Digest) || DigestBytes(object.Bytes) != object.Digest {
			return deny("DIGEST_MISMATCH", "$.objects", "object identity or digest is invalid")
		}
		if existing, ok := store.values[object.ID]; ok {
			if existing.Digest != object.Digest || !bytes.Equal(existing.Bytes, object.Bytes) {
				return deny("ARTIFACT_DRIFT", "$.objects", "object ID is already bound to different bytes")
			}
			continue
		}
		if prior, ok := staged[object.ID]; ok && prior.Digest != object.Digest {
			return deny("ARTIFACT_DRIFT", "$.objects", "batch contains conflicting object IDs")
		}
		staged[object.ID] = Object{ID: object.ID, Digest: object.Digest, Bytes: bytes.Clone(object.Bytes)}
		if object.ID == store.failID {
			return deny("PARTIAL_PUBLICATION", "$.objects", "staged storage failure; no objects committed")
		}
	}
	for id, object := range staged {
		store.values[id] = object
	}
	return nil
}
