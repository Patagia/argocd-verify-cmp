package verify

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
)

// AllVerifier requires ALL wrapped verifiers to pass (AND logic).
// Used for multi-party signing requirements such as upstream key + internal blessing.
type AllVerifier struct {
	verifiers []Verifier
}

// NewAllVerifier wraps one or more verifiers, all of which must pass.
func NewAllVerifier(verifiers ...Verifier) *AllVerifier {
	return &AllVerifier{verifiers: verifiers}
}

func (a *AllVerifier) Verify(ctx context.Context, ref name.Reference) error {
	var errs []error
	for _, v := range a.verifiers {
		if err := v.Verify(ctx, ref); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%d of %d verifier(s) failed: %w", len(errs), len(a.verifiers), errors.Join(errs...))
	}
	return nil
}
