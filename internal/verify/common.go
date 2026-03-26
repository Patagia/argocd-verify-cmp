package verify

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"
)

// verifyWithOpts runs cosign signature verification using the provided opts,
// falling back to Sigstore bundle format if no classic signatures are found.
// label identifies the verifier in log and error messages (e.g. "key /path/to/key.pub").
func verifyWithOpts(ctx context.Context, ref name.Reference, opts *cosign.CheckOpts, label string) error {
	sigs, _, err := cosign.VerifyImageSignatures(ctx, ref, opts)
	if err == nil {
		fmt.Fprintf(os.Stderr, "verify-cmp: %d signature(s) verified with %s\n", len(sigs), label)
		return nil
	}

	// Fall back to Sigstore bundle format (application/vnd.dev.sigstore.bundle.v0.3+json)
	// used by newer cosign CLI versions. VerifyImageSignatures only handles the classic
	// .sig tag format and the legacy OCI referrer type.
	var noSigs *cosign.ErrNoSignaturesFound
	if !errors.As(err, &noSigs) {
		return fmt.Errorf("signature verification failed (%s) (ref: %s): %w", label, ref, err)
	}

	bundles, hash, err := cosign.GetBundles(ctx, ref, opts.RegistryClientOpts)
	if err != nil || len(bundles) == 0 {
		return fmt.Errorf("signature verification failed (%s) (ref: %s): no signatures or bundles found", label, ref)
	}
	digestBytes, err := hex.DecodeString(hash.Hex)
	if err != nil {
		return fmt.Errorf("decoding image digest: %w", err)
	}
	artifactPolicy := sgverify.WithArtifactDigest(hash.Algorithm, digestBytes)
	for _, bundle := range bundles {
		if _, verifyErr := cosign.VerifyNewBundle(ctx, opts, artifactPolicy, bundle); verifyErr == nil {
			fmt.Fprintf(os.Stderr, "verify-cmp: bundle signature verified with %s\n", label)
			return nil
		}
	}
	return fmt.Errorf("signature verification failed (%s) (ref: %s): no valid bundle signatures found", label, ref)
}
