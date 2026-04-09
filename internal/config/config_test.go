package config_test

import (
	"os"
	"testing"

	"github.com/Patagia/argocd-verify-cmp/internal/config"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

func TestLoad_KeyMode(t *testing.T) {
	path := writeConfig(t, `
verification:
  mode: key
  key:
    path: /etc/cosign/cosign.pub
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Verification.Mode != "key" {
		t.Errorf("mode = %q, want \"key\"", cfg.Verification.Mode)
	}
	if cfg.Verification.Key.Path != "/etc/cosign/cosign.pub" {
		t.Errorf("key.path = %q", cfg.Verification.Key.Path)
	}
}

func TestLoad_KMSMode(t *testing.T) {
	path := writeConfig(t, `
verification:
  mode: kms
  kms:
    ref: hashicorp://vault/transit/keys/cosign
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Verification.KMS.Ref != "hashicorp://vault/transit/keys/cosign" {
		t.Errorf("kms.ref = %q", cfg.Verification.KMS.Ref)
	}
}

func TestLoad_Defaults(t *testing.T) {
	path := writeConfig(t, `
verification:
  mode: key
  key:
    path: /etc/cosign/cosign.pub
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Referrers.ExtractDir != "manifests" {
		t.Errorf("extractDir default = %q, want \"manifests\"", cfg.Referrers.ExtractDir)
	}
	if cfg.Referrers.ManifestMediaType != "application/vnd.acme.k8s-manifests.v1+tar" {
		t.Errorf("manifestMediaType default = %q", cfg.Referrers.ManifestMediaType)
	}
}

func TestLoad_ExplicitValuesOverrideDefaults(t *testing.T) {
	path := writeConfig(t, `
verification:
  mode: key
  key:
    path: /etc/cosign/cosign.pub
referrers:
  extractDir: custom/manifests
  manifestMediaType: application/vnd.myco.manifests.v2+tar
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Referrers.ExtractDir != "custom/manifests" {
		t.Errorf("extractDir = %q, want \"custom/manifests\"", cfg.Referrers.ExtractDir)
	}
	if cfg.Referrers.ManifestMediaType != "application/vnd.myco.manifests.v2+tar" {
		t.Errorf("manifestMediaType = %q", cfg.Referrers.ManifestMediaType)
	}
}

func TestLoad_AbsoluteExtractDirRejected(t *testing.T) {
	path := writeConfig(t, `
verification:
  mode: key
  key:
    path: /etc/cosign/cosign.pub
referrers:
  extractDir: /tmp/manifests
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for absolute extractDir, got nil")
	}
}

func TestLoad_AdditionalAndAllowedRegistries(t *testing.T) {
	path := writeConfig(t, `
verification:
  mode: key
  key:
    path: /etc/cosign/cosign.pub
  additional:
    - mode: key
      key:
        path: /etc/cosign/old.pub
    - mode: kms
      kms:
        ref: awskms://my-key
  allowedRegistries:
    - registry.internal.example.com
    - registry2.internal.example.com
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Verification.Additional) != 2 {
		t.Errorf("additional len = %d, want 2", len(cfg.Verification.Additional))
	}
	if cfg.Verification.Additional[0].Mode != "key" {
		t.Errorf("additional[0].mode = %q, want \"key\"", cfg.Verification.Additional[0].Mode)
	}
	if cfg.Verification.Additional[1].Mode != "kms" {
		t.Errorf("additional[1].mode = %q, want \"kms\"", cfg.Verification.Additional[1].Mode)
	}
	if len(cfg.Verification.AllowedRegistries) != 2 {
		t.Errorf("allowedRegistries len = %d, want 2", len(cfg.Verification.AllowedRegistries))
	}
}

func TestLoad_Required(t *testing.T) {
	path := writeConfig(t, `
verification:
  mode: key
  key:
    path: /etc/cosign/cosign.pub
  required:
    - mode: key
      key:
        path: /etc/cosign/blessing.pub
    - mode: cert
      cert:
        path: /etc/cosign/internal-ca.pem
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Verification.Required) != 2 {
		t.Errorf("required len = %d, want 2", len(cfg.Verification.Required))
	}
	if cfg.Verification.Required[0].Mode != "key" {
		t.Errorf("required[0].mode = %q, want \"key\"", cfg.Verification.Required[0].Mode)
	}
	if cfg.Verification.Required[1].Mode != "cert" {
		t.Errorf("required[1].mode = %q, want \"cert\"", cfg.Verification.Required[1].Mode)
	}
}

func TestLoad_MissingMode(t *testing.T) {
	path := writeConfig(t, `
verification:
  key:
    path: /etc/cosign/cosign.pub
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for missing mode, got nil")
	}
}

func TestLoad_KeyModeWithoutPath(t *testing.T) {
	path := writeConfig(t, `
verification:
  mode: key
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for key mode without path, got nil")
	}
}

func TestLoad_KMSModeWithoutRef(t *testing.T) {
	path := writeConfig(t, `
verification:
  mode: kms
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for kms mode without ref, got nil")
	}
}

func TestLoad_UnknownMode(t *testing.T) {
	path := writeConfig(t, `
verification:
  mode: magic
  key:
    path: /etc/cosign/cosign.pub
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for unknown mode, got nil")
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := config.Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	path := writeConfig(t, `{not: valid: yaml: [}`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

func TestLoad_TLSConfig(t *testing.T) {
	path := writeConfig(t, `
verification:
  mode: key
  key:
    path: /etc/cosign/cosign.pub
registry:
  dockerConfigPath: /etc/docker/config.json
  tls:
    insecure: false
    caCertPath: /etc/verify-cmp/ca.crt
    skipVerify: true
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Registry.TLS.SkipVerify != true {
		t.Error("tls.skipVerify should be true")
	}
	if cfg.Registry.TLS.CACertPath != "/etc/verify-cmp/ca.crt" {
		t.Errorf("tls.caCertPath = %q", cfg.Registry.TLS.CACertPath)
	}
}

func TestLoad_AirgapConfig(t *testing.T) {
	path := writeConfig(t, `
verification:
  mode: key
  key:
    path: /etc/cosign/cosign.pub
airgap:
  skipTlog: true
  tufRoot: /etc/verify-cmp/tuf
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Airgap.SkipTlog {
		t.Error("airgap.skipTlog should be true")
	}
	if cfg.Airgap.TUFRoot != "/etc/verify-cmp/tuf" {
		t.Errorf("airgap.tufRoot = %q", cfg.Airgap.TUFRoot)
	}
}
