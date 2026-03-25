package verify

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
)

// MultiVerifier tries each Verifier in order and succeeds on the first pass.
// Used for key rotation: primary key first, then additional keys.
type MultiVerifier struct {
	verifiers []Verifier
}

// NewMultiVerifier wraps one or more verifiers. If only one is provided the
// overhead is minimal but the interface is consistent.
func NewMultiVerifier(verifiers ...Verifier) *MultiVerifier {
	return &MultiVerifier{verifiers: verifiers}
}

func (m *MultiVerifier) Verify(ctx context.Context, ref name.Reference) error {
	var errs []error
	for _, v := range m.verifiers {
		if err := v.Verify(ctx, ref); err != nil {
			errs = append(errs, err)
			continue
		}
		return nil
	}
	return fmt.Errorf("all %d verifier(s) failed: %w", len(m.verifiers), errors.Join(errs...))
}
