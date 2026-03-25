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
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

// KeyVerifier verifies cosign signatures using a static PEM public key file.
type KeyVerifier struct {
	keyPath   string
	checkOpts *cosign.CheckOpts
}

// NewKeyVerifier creates a KeyVerifier for the given public key path.
func NewKeyVerifier(keyPath string, checkOpts *cosign.CheckOpts) (*KeyVerifier, error) {
	if _, err := os.Stat(keyPath); err != nil {
		return nil, fmt.Errorf("public key not found at %s: %w", keyPath, err)
	}
	return &KeyVerifier{keyPath: keyPath, checkOpts: checkOpts}, nil
}

func (v *KeyVerifier) Verify(ctx context.Context, ref name.Reference) error {
	keyBytes, err := os.ReadFile(v.keyPath)
	if err != nil {
		return fmt.Errorf("reading public key %s: %w", v.keyPath, err)
	}
	pubKey, err := cryptoutils.UnmarshalPEMToPublicKey(keyBytes)
	if err != nil {
		return fmt.Errorf("parsing public key %s: %w", v.keyPath, err)
	}
	sv, err := signature.LoadVerifier(pubKey, crypto.SHA256)
	if err != nil {
		return fmt.Errorf("loading verifier for %s: %w", v.keyPath, err)
	}

	opts := *v.checkOpts
	opts.SigVerifier = sv

	sigs, _, err := cosign.VerifyImageSignatures(ctx, ref, &opts)
	if err == nil {
		fmt.Fprintf(os.Stderr, "verify-cmp: %d signature(s) verified with key %s\n", len(sigs), v.keyPath)
		return nil
	}

	// Fall back to Sigstore bundle format (application/vnd.dev.sigstore.bundle.v0.3+json)
	// used by newer cosign CLI versions. VerifyImageSignatures only handles the classic
	// .sig tag format and the legacy OCI referrer type.
	var noSigs *cosign.ErrNoSignaturesFound
	if !errors.As(err, &noSigs) {
		return fmt.Errorf("signature verification failed (key %s) (ref: %s): %w", v.keyPath, ref.String(), err)
	}

	bundles, hash, err := cosign.GetBundles(ctx, ref, opts.RegistryClientOpts)
	if err != nil || len(bundles) == 0 {
		return fmt.Errorf("signature verification failed (key %s) (ref: %s): no signatures or bundles found", v.keyPath, ref.String())
	}
	digestBytes, err := hex.DecodeString(hash.Hex)
	if err != nil {
		return fmt.Errorf("decoding image digest: %w", err)
	}
	artifactPolicy := sgverify.WithArtifactDigest(hash.Algorithm, digestBytes)
	for _, bundle := range bundles {
		if _, verifyErr := cosign.VerifyNewBundle(ctx, &opts, artifactPolicy, bundle); verifyErr == nil {
			fmt.Fprintf(os.Stderr, "verify-cmp: bundle signature verified with key %s\n", v.keyPath)
			return nil
		}
	}
	return fmt.Errorf("signature verification failed (key %s) (ref: %s): no valid bundle signatures found", v.keyPath, ref.String())
}
