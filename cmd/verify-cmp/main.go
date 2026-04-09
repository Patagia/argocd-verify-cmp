package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	gcrremote "github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/spf13/cobra"

	"github.com/Patagia/argocd-verify-cmp/internal/config"
	"github.com/Patagia/argocd-verify-cmp/internal/manifest"
	"github.com/Patagia/argocd-verify-cmp/internal/referrers"
	"github.com/Patagia/argocd-verify-cmp/internal/verify"
)

const defaultConfigPath = "/tmp/verify-cmp/config.yaml"

func main() {
	root := &cobra.Command{
		Use:           "verify-cmp",
		Short:         "ArgoCD CMP: verify cosign signatures and generate manifests from OCI referrers",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newFetchCmd(), newGenerateCmd())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "verify-cmp:", err)
		os.Exit(1)
	}
}

func configPath() string {
	if p := os.Getenv("VERIFY_CMP_CONFIG"); p != "" {
		return p
	}
	return defaultConfigPath
}

// newFetchCmd returns the `fetch` subcommand.
// ArgoCD calls this instead of cloning the source; it verifies the cosign
// signature, extracts the manifest bundle to the configured extractDir, and
// writes .argocd-cmp-fetch-result.json with the resolved revision and verify
// output for ArgoCD to surface in the UI.
func newFetchCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "fetch",
		Short: "Verify cosign signature and extract manifest bundle",
		RunE:  runFetch,
	}
}

func runFetch(_ *cobra.Command, _ []string) error {
	ctx := context.Background()

	repoURL := os.Getenv("ARGOCD_APP_SOURCE_REPO_URL")
	if repoURL == "" {
		return fmt.Errorf("ARGOCD_APP_SOURCE_REPO_URL is not set")
	}

	// Layer 2 safety check: passthrough for non-OCI sources.
	if !strings.HasPrefix(repoURL, "oci://") {
		fmt.Fprintf(os.Stderr, "verify-cmp: ARGOCD_APP_SOURCE_REPO_URL=%q is not an OCI source, skipping\n", repoURL)
		return nil
	}

	cfg, err := config.Load(configPath())
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Build OCI reference from ARGOCD_APP_SOURCE_REPO_URL + TARGET_REVISION.
	rawRef := strings.TrimPrefix(repoURL, "oci://")
	revision := os.Getenv("ARGOCD_APP_SOURCE_TARGET_REVISION")
	switch {
	case strings.HasPrefix(revision, "sha256:"):
		rawRef = rawRef + "@" + revision
	case revision != "":
		rawRef = rawRef + ":" + revision
	}

	nameOpts := []name.Option{}
	if cfg.Registry.TLS.Insecure {
		nameOpts = append(nameOpts, name.Insecure)
	}
	ref, err := name.ParseReference(rawRef, nameOpts...)
	if err != nil {
		return fmt.Errorf("parsing OCI reference %q: %w", rawRef, err)
	}

	// Validate against allowed registries.
	if err := checkAllowedRegistry(ref, cfg.Verification.AllowedRegistries); err != nil {
		return err
	}

	// Build shared transport and keychain.
	transport, err := buildTransport(cfg)
	if err != nil {
		return err
	}
	keychain := buildKeychain(cfg)

	// Build cosign CheckOpts.
	checkOpts := buildCheckOpts(cfg, transport, keychain)

	// Build verifier chain: primary + additional keys.
	v, err := buildVerifier(cfg, checkOpts)
	if err != nil {
		return err
	}

	// Resolve the source ref to a digest so we can report an immutable revision.
	gcrOpts := []gcrremote.Option{
		gcrremote.WithContext(ctx),
		gcrremote.WithAuthFromKeychain(keychain),
		gcrremote.WithTransport(transport),
	}
	headDesc, err := gcrremote.Head(ref, gcrOpts...)
	if err != nil {
		return fmt.Errorf("resolving image digest for %s: %w", ref, err)
	}
	resolvedRevision := headDesc.Digest.String()

	// Best-effort: read OCI image labels for the UI metadata panel.
	// Returns nil for raw artifacts (e.g. oras-pushed bundles) that carry no
	// standard image config.
	meta := fetchMetadata(ref, gcrOpts)

	// Determine discovery path: inspect the artifactType of the source ref.
	// If it matches the configured bundle media type, the source IS the bundle
	// (standalone). Otherwise treat it as the app image and look for referrers.
	artifactType, err := referrers.ArtifactType(ctx, ref, transport, keychain)
	if err != nil {
		return fmt.Errorf("fetching manifest artifact type: %w", err)
	}

	if artifactType == cfg.Referrers.ManifestMediaType {
		// Standalone: the source ref is the manifest bundle itself.
		fmt.Fprintf(os.Stderr, "verify-cmp: source is a standalone manifest bundle, verifying signature on %s\n", ref)
		if err := v.Verify(ctx, ref); err != nil {
			return fmt.Errorf("signature verification: %w", err)
		}
		if err := referrers.ExtractByRef(ctx, ref, cfg.Referrers.ExtractDir, transport, keychain); err != nil {
			return fmt.Errorf("extracting manifest bundle: %w", err)
		}
	} else {
		// Referrers: the source is the app image. Verify it, then find and
		// extract the manifest bundle attached as a referrer.
		fmt.Fprintf(os.Stderr, "verify-cmp: verifying signature on app image %s\n", ref)
		if err := v.Verify(ctx, ref); err != nil {
			return fmt.Errorf("signature verification: %w", err)
		}
		fmt.Fprintf(os.Stderr, "verify-cmp: discovering referrer with media type %q\n", cfg.Referrers.ManifestMediaType)
		desc, err := referrers.Find(
			ctx, ref,
			cfg.Referrers.ManifestMediaType,
			cfg.Referrers.EnableTagFallback,
			transport, keychain,
			cfg.Registry.DockerConfigPath,
		)
		if err != nil {
			return fmt.Errorf("finding manifest bundle referrer: %w", err)
		}
		fmt.Fprintf(os.Stderr, "verify-cmp: found referrer %s\n", desc.Digest)
		if err := referrers.Extract(ctx, ref, desc, cfg.Referrers.ExtractDir, transport, keychain); err != nil {
			return fmt.Errorf("extracting manifest bundle: %w", err)
		}
	}

	return writeFetchResult(resolvedRevision, "Verified OK", meta)
}

// FetchResultMetadata holds optional OCI-image-label metadata to surface in
// the ArgoCD UI revision panel. All fields are sourced from standard
// org.opencontainers.image.* labels and are omitted when empty.
type FetchResultMetadata struct {
	Version     string `json:"version,omitempty"`
	Description string `json:"description,omitempty"`
	Authors     string `json:"authors,omitempty"`
	CreatedAt   string `json:"createdAt,omitempty"`
	SourceURL   string `json:"sourceURL,omitempty"`
	DocsURL     string `json:"docsURL,omitempty"`
}

// fetchMetadata reads OCI manifest annotations from ref and returns a populated
// FetchResultMetadata, or nil when no useful annotations are present. Using
// manifest annotations (set via `oras --annotation`) works for both regular
// OCI images and raw artifacts.
func fetchMetadata(ref name.Reference, gcrOpts []gcrremote.Option) *FetchResultMetadata {
	rd, err := gcrremote.Get(ref, gcrOpts...)
	if err != nil {
		return nil
	}
	var manifest struct {
		Annotations map[string]string `json:"annotations"`
	}
	if err := json.Unmarshal(rd.Manifest, &manifest); err != nil || len(manifest.Annotations) == 0 {
		return nil
	}
	ann := manifest.Annotations

	source := ann["org.opencontainers.image.source"]
	gitRev := ann["org.opencontainers.image.revision"]

	m := &FetchResultMetadata{
		Version:     ann["org.opencontainers.image.version"],
		Description: ann["org.opencontainers.image.description"],
		Authors:     ann["org.opencontainers.image.authors"],
		CreatedAt:   ann["org.opencontainers.image.created"],
		DocsURL:     source,
	}
	switch {
	case source != "" && gitRev != "":
		m.SourceURL = source + "/commit/" + gitRev
	case source != "":
		m.SourceURL = source
	}

	if m.Version == "" && m.Description == "" && m.Authors == "" &&
		m.CreatedAt == "" && m.SourceURL == "" && m.DocsURL == "" {
		return nil
	}
	return m
}

// writeFetchResult writes .argocd-cmp-fetch-result.json to the current working
// directory so ArgoCD can surface the resolved revision and verify output.
func writeFetchResult(revision, verifyResult string, meta *FetchResultMetadata) error {
	result := struct {
		Revision     string               `json:"revision,omitempty"`
		VerifyResult string               `json:"verifyResult,omitempty"`
		Metadata     *FetchResultMetadata `json:"metadata,omitempty"`
	}{
		Revision:     revision,
		VerifyResult: verifyResult,
		Metadata:     meta,
	}
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshaling fetch result: %w", err)
	}
	if err := os.WriteFile(".argocd-cmp-fetch-result.json", data, 0o644); err != nil {
		return fmt.Errorf("writing .argocd-cmp-fetch-result.json: %w", err)
	}
	return nil
}

// newGenerateCmd returns the `generate` subcommand.
// ArgoCD calls this after fetch; it prints manifests to stdout.
func newGenerateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "generate",
		Short: "Print extracted manifests to stdout",
		RunE:  runGenerate,
	}
}

func runGenerate(_ *cobra.Command, _ []string) error {
	cfg, err := config.Load(configPath())
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	subPath := os.Getenv("ARGOCD_APP_SOURCE_PATH")
	return manifest.Generate(cfg.Referrers.ExtractDir, subPath)
}

// buildTransport creates a custom http.Transport applying TLS settings from cfg.
func buildTransport(cfg *config.Config) (*http.Transport, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	tlsCfg := &tls.Config{}

	if cfg.Registry.TLS.CACertPath != "" {
		caCert, err := os.ReadFile(cfg.Registry.TLS.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("reading CA cert %s: %w", cfg.Registry.TLS.CACertPath, err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("no valid certificates found in %s", cfg.Registry.TLS.CACertPath)
		}
		tlsCfg.RootCAs = pool
	}

	if cfg.Registry.TLS.SkipVerify {
		fmt.Fprintln(os.Stderr, "verify-cmp: WARNING: TLS certificate verification is disabled")
		tlsCfg.InsecureSkipVerify = true //nolint:gosec
	}

	transport.TLSClientConfig = tlsCfg
	return transport, nil
}

// buildKeychain returns a keychain that reads Docker credentials from the
// configured dockerConfigPath (or the standard locations if not set).
func buildKeychain(cfg *config.Config) authn.Keychain {
	if cfg.Registry.DockerConfigPath != "" {
		dir := filepath.Dir(cfg.Registry.DockerConfigPath)
		os.Setenv("DOCKER_CONFIG", dir) //nolint:errcheck
	}
	return authn.DefaultKeychain
}

// buildCheckOpts constructs cosign.CheckOpts from the loaded config.
func buildCheckOpts(cfg *config.Config, transport http.RoundTripper, keychain authn.Keychain) *cosign.CheckOpts {
	registryOpts := []ociremote.Option{
		ociremote.WithRemoteOptions(
			gcrremote.WithAuthFromKeychain(keychain),
			gcrremote.WithTransport(transport),
		),
	}
	if cfg.Registry.TLS.Insecure {
		registryOpts = append(registryOpts, ociremote.WithNameOptions(name.Insecure))
	}

	return &cosign.CheckOpts{
		IgnoreTlog:         cfg.Airgap.SkipTlog,
		IgnoreSCT:          cfg.Airgap.SkipTlog,
		RegistryClientOpts: registryOpts,
		// Try OCI 1.1 referrers first (used by newer cosign/Zot), then fall
		// back to the legacy sha256-<digest>.sig tag scheme.
		ExperimentalOCI11: true,
	}
}

// buildVerifier constructs a Verifier from config.
// The primary verifier plus any additional verifiers are composed into a
// MultiVerifier (OR logic). If required verifiers are configured they are
// wrapped with the OR chain in an AllVerifier (AND logic).
func buildVerifier(cfg *config.Config, checkOpts *cosign.CheckOpts) (verify.Verifier, error) {
	primary, err := buildEntryVerifier(config.VerifierEntryConfig{
		Mode: cfg.Verification.Mode,
		Key:  cfg.Verification.Key,
		KMS:  cfg.Verification.KMS,
		Cert: cfg.Verification.Cert,
	}, checkOpts)
	if err != nil {
		return nil, err
	}
	orChain := []verify.Verifier{primary}

	for i, entry := range cfg.Verification.Additional {
		v, err := buildEntryVerifier(entry, checkOpts)
		if err != nil {
			return nil, fmt.Errorf("additional[%d]: %w", i, err)
		}
		orChain = append(orChain, v)
	}

	if len(cfg.Verification.Required) == 0 {
		return verify.NewMultiVerifier(orChain...), nil
	}

	andChain := []verify.Verifier{verify.NewMultiVerifier(orChain...)}
	for i, entry := range cfg.Verification.Required {
		v, err := buildEntryVerifier(entry, checkOpts)
		if err != nil {
			return nil, fmt.Errorf("required[%d]: %w", i, err)
		}
		andChain = append(andChain, v)
	}
	return verify.NewAllVerifier(andChain...), nil
}

// buildEntryVerifier constructs a single Verifier from a VerifierEntryConfig.
func buildEntryVerifier(entry config.VerifierEntryConfig, checkOpts *cosign.CheckOpts) (verify.Verifier, error) {
	switch entry.Mode {
	case "kms":
		return verify.NewKMSVerifier(entry.KMS.Ref, checkOpts), nil
	case "key":
		return verify.NewKeyVerifier(entry.Key.Path, checkOpts)
	case "cert":
		identities := make([]cosign.Identity, len(entry.Cert.Identities))
		for i, id := range entry.Cert.Identities {
			identities[i] = cosign.Identity{
				Issuer:        id.Issuer,
				Subject:       id.Subject,
				IssuerRegExp:  id.IssuerRegExp,
				SubjectRegExp: id.SubjectRegExp,
			}
		}
		return verify.NewCertVerifier(entry.Cert.Path, entry.Cert.IntermediateCertsPath, identities, checkOpts)
	case "attestation":
		cfg := entry.Attestation
		identities := make([]cosign.Identity, len(cfg.Cert.Identities))
		for i, id := range cfg.Cert.Identities {
			identities[i] = cosign.Identity{
				Issuer:        id.Issuer,
				Subject:       id.Subject,
				IssuerRegExp:  id.IssuerRegExp,
				SubjectRegExp: id.SubjectRegExp,
			}
		}
		return verify.NewAttestationVerifier(
			cfg.PredicateType,
			cfg.Claims,
			cfg.SigningMode,
			cfg.Key.Path,
			cfg.KMS.Ref,
			cfg.Cert.Path,
			cfg.Cert.IntermediateCertsPath,
			identities,
			checkOpts,
		), nil
	default:
		return nil, fmt.Errorf("unknown verification mode %q", entry.Mode)
	}
}

// checkAllowedRegistry rejects refs whose registry is not in the allowlist.
// If allowedRegistries is empty, all registries are permitted.
func checkAllowedRegistry(ref name.Reference, allowed []string) error {
	if len(allowed) == 0 {
		return nil
	}
	registry := ref.Context().RegistryStr()
	if slices.Contains(allowed, registry) {
		return nil
	}
	return fmt.Errorf("registry %q is not in allowedRegistries: %v", registry, allowed)
}
