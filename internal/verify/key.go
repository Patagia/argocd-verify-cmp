package verify

import (
	"context"
	"crypto"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v3/pkg/cosign"
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
	return verifyWithOpts(ctx, ref, &opts, "key "+v.keyPath)
}
