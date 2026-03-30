package verify

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
)

// AttestationVerifier checks that a signed cosign attestation with the
// configured predicateType is attached to the image, and optionally asserts
// top-level predicate fields against the configured claims map.
type AttestationVerifier struct {
	predicateType         string
	claims                map[string]string
	signingMode           string // "key", "kms", or "cert"
	keyPath               string
	kmsRef                string
	certPath              string
	intermediateCertsPath string
	identities            []cosign.Identity
	checkOpts             *cosign.CheckOpts
}

// NewAttestationVerifier creates an AttestationVerifier. signingMode selects
// how the attestation signature is verified: "key" (keyPath), "kms" (kmsRef),
// or "cert" (certPath / intermediateCertsPath / identities).
func NewAttestationVerifier(
	predicateType string,
	claims map[string]string,
	signingMode, keyPath, kmsRef, certPath, intermediateCertsPath string,
	identities []cosign.Identity,
	checkOpts *cosign.CheckOpts,
) *AttestationVerifier {
	return &AttestationVerifier{
		predicateType:         predicateType,
		claims:                claims,
		signingMode:           signingMode,
		keyPath:               keyPath,
		kmsRef:                kmsRef,
		certPath:              certPath,
		intermediateCertsPath: intermediateCertsPath,
		identities:            identities,
		checkOpts:             checkOpts,
	}
}

func (a *AttestationVerifier) Verify(ctx context.Context, ref name.Reference) error {
	opts := *a.checkOpts
	opts.ClaimVerifier = cosign.IntotoSubjectClaimVerifier

	switch a.signingMode {
	case "key":
		keyBytes, err := os.ReadFile(a.keyPath)
		if err != nil {
			return fmt.Errorf("attestation: reading key %s: %w", a.keyPath, err)
		}
		pubKey, err := cryptoutils.UnmarshalPEMToPublicKey(keyBytes)
		if err != nil {
			return fmt.Errorf("attestation: parsing key %s: %w", a.keyPath, err)
		}
		sv, err := signature.LoadVerifier(pubKey, crypto.SHA256)
		if err != nil {
			return fmt.Errorf("attestation: loading verifier for %s: %w", a.keyPath, err)
		}
		opts.SigVerifier = sv
	case "kms":
		sv, err := kms.Get(ctx, a.kmsRef, crypto.SHA256)
		if err != nil {
			return fmt.Errorf("attestation: loading KMS key %s: %w", a.kmsRef, err)
		}
		opts.SigVerifier = sv
	case "cert":
		rootPool, err := LoadCertPool(a.certPath)
		if err != nil {
			return err
		}
		opts.RootCerts = rootPool
		if a.intermediateCertsPath != "" {
			intermediatePool, err := LoadCertPool(a.intermediateCertsPath)
			if err != nil {
				return err
			}
			opts.IntermediateCerts = intermediatePool
		}
		if len(a.identities) > 0 {
			opts.Identities = a.identities
		}
	}

	attestations, _, err := cosign.VerifyImageAttestations(ctx, ref, &opts)
	if err != nil {
		return fmt.Errorf("attestation verification failed (ref: %s): %w", ref, err)
	}

	for _, att := range attestations {
		payload, err := att.Payload()
		if err != nil {
			continue
		}
		if matchesAttestation(payload, a.predicateType, a.claims) {
			return nil
		}
	}

	if len(a.claims) > 0 {
		return fmt.Errorf("no attestation with predicateType %q and matching claims found (ref: %s)", a.predicateType, ref)
	}
	return fmt.Errorf("no attestation with predicateType %q found (ref: %s)", a.predicateType, ref)
}

// matchesAttestation reports whether the raw DSSE payload bytes match the given
// predicateType and all claims (if any). Claims are compared as strings using
// fmt.Sprint so bool/number predicate fields can be matched from config strings.
func matchesAttestation(payload []byte, predicateType string, claims map[string]string) bool {
	var envelope struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return false
	}
	if envelope.PayloadType != predicateType {
		return false
	}
	if len(claims) == 0 {
		return true
	}
	predicateJSON, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return false
	}
	var predicate map[string]any
	if err := json.Unmarshal(predicateJSON, &predicate); err != nil {
		return false
	}
	for k, want := range claims {
		got, ok := predicate[k]
		if !ok || fmt.Sprint(got) != want {
			return false
		}
	}
	return true
}
