package verify

import (
	"context"

	"github.com/google/go-containerregistry/pkg/name"
)

// Verifier verifies a cosign signature on an OCI image.
type Verifier interface {
	Verify(ctx context.Context, ref name.Reference) error
}
