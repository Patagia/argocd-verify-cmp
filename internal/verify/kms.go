package verify

import (
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"
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

	sigs, _, err := cosign.VerifyImageSignatures(ctx, ref, &opts)
	if err == nil {
		fmt.Fprintf(os.Stderr, "verify-cmp: %d signature(s) verified with KMS %s\n", len(sigs), v.kmsRef)
		return nil
	}

	// Fall back to Sigstore bundle format (application/vnd.dev.sigstore.bundle.v0.3+json)
	// used by newer cosign CLI versions. VerifyImageSignatures only handles the classic
	// .sig tag format and the legacy OCI referrer type.
	var noSigs *cosign.ErrNoSignaturesFound
	if !errors.As(err, &noSigs) {
		return fmt.Errorf("signature verification failed (KMS %s) (ref: %s): %w", v.kmsRef, ref.String(), err)
	}

	bundles, hash, err := cosign.GetBundles(ctx, ref, opts.RegistryClientOpts)
	if err != nil || len(bundles) == 0 {
		return fmt.Errorf("signature verification failed (KSM %s) (ref: %s): no signatures or bundles found", v.kmsRef, ref.String())
	}
	digestBytes, err := hex.DecodeString(hash.Hex)
	if err != nil {
		return fmt.Errorf("decoding image digest: %w", err)
	}
	artifactPolicy := sgverify.WithArtifactDigest(hash.Algorithm, digestBytes)
	for _, bundle := range bundles {
		if _, verifyErr := cosign.VerifyNewBundle(ctx, &opts, artifactPolicy, bundle); verifyErr == nil {
			fmt.Fprintf(os.Stderr, "verify-cmp: bundle signature verified with KMS %s\n", v.kmsRef)
			return nil
		}
	}
	return fmt.Errorf("signature verification failed (KMS %s) (ref: %s): no valid bundle signatures found", v.kmsRef, ref.String())
}
