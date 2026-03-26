package verify

import (
	"context"
	"crypto"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/signature/kms"

	// Import KMS provider plugins so they self-register.
	_ "github.com/sigstore/sigstore/pkg/signature/kms/aws"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/gcp"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/hashivault"
)

// KMSVerifier verifies cosign signatures using a KMS-backed key.
type KMSVerifier struct {
	kmsRef    string
	checkOpts *cosign.CheckOpts
}

// NewKMSVerifier creates a KMSVerifier for the given KMS key reference
// (e.g. "hashicorp://vault/transit/keys/cosign", "awskms://...", "gcpkms://...").
func NewKMSVerifier(kmsRef string, checkOpts *cosign.CheckOpts) *KMSVerifier {
	return &KMSVerifier{kmsRef: kmsRef, checkOpts: checkOpts}
}

func (v *KMSVerifier) Verify(ctx context.Context, ref name.Reference) error {
	sv, err := kms.Get(ctx, v.kmsRef, crypto.SHA256)
	if err != nil {
		return fmt.Errorf("loading KMS key %s: %w", v.kmsRef, err)
	}

	opts := *v.checkOpts
	opts.SigVerifier = sv
	return verifyWithOpts(ctx, ref, &opts, "KMS "+v.kmsRef)
}
