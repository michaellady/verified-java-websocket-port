package protocol

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

var (
	ErrPromotionConflict = errors.New("promotion key already contains different bytes")
	ErrPartialPromotion  = errors.New("transactional promotion rejected incomplete batch")
)

type PromotionObject struct {
	Key    string `json:"key"`
	Digest string `json:"digest"`
	Bytes  []byte `json:"bytes"`
}

type PromotionBatch struct {
	SnapshotID     string            `json:"snapshot_id"`
	SnapshotDigest string            `json:"snapshot_digest"`
	Objects        []PromotionObject `json:"objects"`
}

// TransactionalPromoter commits every object or none. Implementations must
// make identical replays idempotent and must never replace different bytes.
type TransactionalPromoter interface {
	Promote(context.Context, PromotionBatch) error
}

type MemoryPromoter struct {
	mu      sync.Mutex
	objects map[string]PromotionObject
	failAt  int
}

func NewMemoryPromoter() *MemoryPromoter {
	return &MemoryPromoter{objects: make(map[string]PromotionObject)}
}

// InjectFailureAt is a deterministic chaos seam. A positive index rejects the
// batch before commit at that object boundary, proving all-or-none behavior.
func (value *MemoryPromoter) InjectFailureAt(index int) {
	value.mu.Lock()
	defer value.mu.Unlock()
	value.failAt = index
}

func (value *MemoryPromoter) Promote(ctx context.Context, batch PromotionBatch) error {
	value.mu.Lock()
	defer value.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if batch.SnapshotID == "" || batch.SnapshotDigest == "" || len(batch.Objects) == 0 {
		return ErrPartialPromotion
	}
	pending := make(map[string]PromotionObject, len(batch.Objects))
	for index, object := range batch.Objects {
		if value.failAt > 0 && index+1 == value.failAt {
			return fmt.Errorf("%w at object %d", ErrPartialPromotion, index+1)
		}
		if object.Key == "" || DigestBytes(object.Bytes) != object.Digest {
			return ErrPartialPromotion
		}
		if prior, exists := value.objects[object.Key]; exists {
			if prior.Digest != object.Digest {
				return ErrPromotionConflict
			}
			continue
		}
		if prior, exists := pending[object.Key]; exists && prior.Digest != object.Digest {
			return ErrPromotionConflict
		}
		pending[object.Key] = PromotionObject{Key: object.Key, Digest: object.Digest, Bytes: append([]byte(nil), object.Bytes...)}
	}
	for key, object := range pending {
		value.objects[key] = object
	}
	return nil
}

func (value *MemoryPromoter) Object(key string) (PromotionObject, bool) {
	value.mu.Lock()
	defer value.mu.Unlock()
	object, exists := value.objects[key]
	object.Bytes = append([]byte(nil), object.Bytes...)
	return object, exists
}

func (value *MemoryPromoter) Count() int {
	value.mu.Lock()
	defer value.mu.Unlock()
	return len(value.objects)
}
