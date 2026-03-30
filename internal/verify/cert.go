package verify

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v3/pkg/cosign"
)

// CertVerifier verifies cosign signatures against a certificate chain.
// rootCertsPath must point to a PEM file with the trusted root CA(s).
// intermediateCertsPath optionally points to a PEM file with intermediate
// CAs needed to complete the chain from the signing cert to the root.
// Identities constrain accepted OIDC subjects/issuers for keyless signatures.
type CertVerifier struct {
	certPath              string
	intermediateCertsPath string
	identities            []cosign.Identity
	checkOpts             *cosign.CheckOpts
}

// NewCertVerifier creates a CertVerifier.
// intermediateCertsPath may be empty if the root CA directly signed the
// signing certificate.
func NewCertVerifier(certPath, intermediateCertsPath string, identities []cosign.Identity, checkOpts *cosign.CheckOpts) (*CertVerifier, error) {
	if _, err := os.Stat(certPath); err != nil {
		return nil, fmt.Errorf("certificate not found at %s: %w", certPath, err)
	}
	if intermediateCertsPath != "" {
		if _, err := os.Stat(intermediateCertsPath); err != nil {
			return nil, fmt.Errorf("intermediate certificates not found at %s: %w", intermediateCertsPath, err)
		}
	}
	return &CertVerifier{
		certPath:              certPath,
		intermediateCertsPath: intermediateCertsPath,
		identities:            identities,
		checkOpts:             checkOpts,
	}, nil
}

func (v *CertVerifier) Verify(ctx context.Context, ref name.Reference) error {
	rootPool, err := LoadCertPool(v.certPath)
	if err != nil {
		return err
	}

	opts := *v.checkOpts
	opts.RootCerts = rootPool

	if v.intermediateCertsPath != "" {
		intermediatePool, err := LoadCertPool(v.intermediateCertsPath)
		if err != nil {
			return err
		}
		opts.IntermediateCerts = intermediatePool
	}

	if len(v.identities) > 0 {
		opts.Identities = v.identities
	}

	return verifyWithOpts(ctx, ref, &opts, "certificate "+v.certPath)
}

// LoadCertPool parses all PEM CERTIFICATE blocks in path into a new x509.CertPool.
func LoadCertPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading certificate file %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate in %s: %w", path, err)
		}
		pool.AddCert(cert)
	}
	return pool, nil
}
