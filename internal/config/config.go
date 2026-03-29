package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level verify-cmp configuration.
type Config struct {
	Verification VerificationConfig `yaml:"verification"`
	Registry     RegistryConfig     `yaml:"registry"`
	Referrers    ReferrersConfig    `yaml:"referrers"`
	Airgap       AirgapConfig       `yaml:"airgap"`
}

type VerificationConfig struct {
	Mode              string     `yaml:"mode"` // "key", "kms", or "cert"
	Key               KeyConfig  `yaml:"key"`
	KMS               KMSConfig  `yaml:"kms"`
	Cert              CertConfig `yaml:"cert"`
	AdditionalKeys    []string   `yaml:"additionalKeys"`
	RequiredKeys      []string   `yaml:"requiredKeys"`
	AllowedRegistries []string   `yaml:"allowedRegistries"`
}

type KeyConfig struct {
	Path string `yaml:"path"`
}

type KMSConfig struct {
	Ref string `yaml:"ref"`
}

// CertConfig configures certificate-based signature verification.
// Path must point to a PEM file containing the root CA certificate(s).
// IntermediateCertsPath optionally points to a PEM file with intermediate
// CA certificates needed to complete the chain from the signing cert to the root.
// Identities constrains which certificate subjects/issuers are accepted;
// if empty, any certificate that chains to the root CA is accepted.
type CertConfig struct {
	Path                 string           `yaml:"path"`
	IntermediateCertsPath string          `yaml:"intermediateCertsPath"`
	Identities           []IdentityConfig `yaml:"identities"`
}

// IdentityConfig constrains acceptable certificate identities.
// Each field is matched literally; use the RegExp variants for pattern matching.
// At least one of Subject/SubjectRegExp and one of Issuer/IssuerRegExp should
// be set when using keyless (Fulcio) signatures.
type IdentityConfig struct {
	Subject       string `yaml:"subject"`
	SubjectRegExp string `yaml:"subjectRegExp"`
	Issuer        string `yaml:"issuer"`
	IssuerRegExp  string `yaml:"issuerRegExp"`
}

type RegistryConfig struct {
	DockerConfigPath string    `yaml:"dockerConfigPath"`
	TLS              TLSConfig `yaml:"tls"`
}

type TLSConfig struct {
	Insecure   bool   `yaml:"insecure"`
	CACertPath string `yaml:"caCertPath"`
	SkipVerify bool   `yaml:"skipVerify"`
}

type ReferrersConfig struct {
	ManifestMediaType string `yaml:"manifestMediaType"`
	ExtractDir        string `yaml:"extractDir"`
	EnableTagFallback bool   `yaml:"enableTagFallback"`
}

type AirgapConfig struct {
	SkipTlog bool   `yaml:"skipTlog"`
	TUFRoot  string `yaml:"tufRoot"`
}

// Load reads and validates the config file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	setDefaults(&cfg)
	if err := validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func setDefaults(cfg *Config) {
	if cfg.Referrers.ExtractDir == "" {
		cfg.Referrers.ExtractDir = "/tmp/manifests"
	}
	if cfg.Referrers.ManifestMediaType == "" {
		cfg.Referrers.ManifestMediaType = "application/vnd.acme.k8s-manifests.v1+tar"
	}
}

func validate(cfg *Config) error {
	switch cfg.Verification.Mode {
	case "key":
		if cfg.Verification.Key.Path == "" {
			return fmt.Errorf("verification.key.path is required when mode is \"key\"")
		}
	case "kms":
		if cfg.Verification.KMS.Ref == "" {
			return fmt.Errorf("verification.kms.ref is required when mode is \"kms\"")
		}
	case "cert":
		if cfg.Verification.Cert.Path == "" {
			return fmt.Errorf("verification.cert.path is required when mode is \"cert\"")
		}
	case "":
		return fmt.Errorf("verification.mode is required (key, kms, or cert)")
	default:
		return fmt.Errorf("verification.mode must be \"key\", \"kms\", or \"cert\", got %q", cfg.Verification.Mode)
	}
	return nil
}
