// Package referrers discovers OCI referrers attached to an image.
// Primary discovery uses the OCI 1.1 referrers API via go-containerregistry.
// If that fails and enableTagFallback is true, it falls back to ORAS tag-based
// referrer discovery which supports pre-OCI-1.1 registries.
package referrers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	gcrremote "github.com/google/go-containerregistry/pkg/v1/remote"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	orasremote "oras.land/oras-go/v2/registry/remote"
	orasauth "oras.land/oras-go/v2/registry/remote/auth"
	orascredentials "oras.land/oras-go/v2/registry/remote/credentials"
)

// ArtifactType fetches the manifest for ref and returns its top-level
// artifactType field. Returns an empty string for regular container images
// that carry no artifactType.
func ArtifactType(ctx context.Context, ref name.Reference, transport http.RoundTripper, keychain authn.Keychain) (string, error) {
	opts := []gcrremote.Option{
		gcrremote.WithContext(ctx),
		gcrremote.WithAuthFromKeychain(keychain),
		gcrremote.WithTransport(transport),
	}
	rd, err := gcrremote.Get(ref, opts...)
	if err != nil {
		return "", fmt.Errorf("fetching manifest for %s: %w", ref, err)
	}
	var m struct {
		ArtifactType string `json:"artifactType"`
	}
	if err := json.Unmarshal(rd.Manifest, &m); err != nil {
		return "", fmt.Errorf("parsing manifest: %w", err)
	}
	return m.ArtifactType, nil
}

// Find returns the first referrer descriptor whose ArtifactType matches
// mediaType. It tries the OCI 1.1 referrers API first; if that fails and
// enableTagFallback is true it falls back to ORAS tag-based discovery.
func Find(
	ctx context.Context,
	imageRef name.Reference,
	mediaType string,
	enableTagFallback bool,
	transport http.RoundTripper,
	keychain authn.Keychain,
	dockerConfigPath string,
) (ocispec.Descriptor, error) {
	gcrOpts := []gcrremote.Option{
		gcrremote.WithContext(ctx),
		gcrremote.WithAuthFromKeychain(keychain),
		gcrremote.WithTransport(transport),
	}

	// Resolve the image to a digest so we can call the referrers endpoint.
	desc, err := gcrremote.Head(imageRef, gcrOpts...)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("resolving image descriptor: %w", err)
	}
	digestRef, err := name.NewDigest(
		imageRef.Context().String() + "@" + desc.Digest.String(),
	)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("building digest reference: %w", err)
	}

	// OCI 1.1 referrers API via go-containerregistry.
	idx, err := gcrremote.Referrers(digestRef, gcrOpts...)
	if err == nil {
		manifest, mErr := idx.IndexManifest()
		if mErr == nil {
			for _, m := range manifest.Manifests {
				at := string(m.ArtifactType)
				if at == "" {
					at = string(m.MediaType)
				}
				if at == mediaType {
					return ocispec.Descriptor{
						MediaType:    string(m.MediaType),
						ArtifactType: at,
						Digest:       digestFromGCR(m.Digest),
						Size:         m.Size,
					}, nil
				}
			}
		}
		if !enableTagFallback {
			return ocispec.Descriptor{}, fmt.Errorf("no referrer with media type %q found (OCI 1.1 referrers API)", mediaType)
		}
		fmt.Fprintf(os.Stderr, "verify-cmp: OCI 1.1 referrers API found no match, trying tag fallback\n")
	} else {
		if !enableTagFallback {
			return ocispec.Descriptor{}, fmt.Errorf("referrers API failed: %w", err)
		}
		fmt.Fprintf(os.Stderr, "verify-cmp: OCI 1.1 referrers API failed (%v), trying tag fallback\n", err)
	}

	// Tag-based fallback via ORAS (handles pre-OCI-1.1 registries).
	return findViaORASTags(ctx, imageRef, desc.Digest.String(), mediaType, transport, dockerConfigPath)
}

// findViaORASTags uses ORAS v2 to discover referrers via the tag-based scheme
// used by older registries that predate the OCI 1.1 referrers API.
func findViaORASTags(
	ctx context.Context,
	imageRef name.Reference,
	_ string, // subject digest (ORAS resolves it internally)
	mediaType string,
	transport http.RoundTripper,
	dockerConfigPath string,
) (ocispec.Descriptor, error) {
	store, err := orascredentials.NewStore(dockerConfigPath, orascredentials.StoreOptions{})
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("loading docker credentials for ORAS: %w", err)
	}

	repo, err := orasremote.NewRepository(imageRef.Context().String())
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("building ORAS repository: %w", err)
	}
	repo.Client = &orasauth.Client{
		Client:     &http.Client{Transport: transport},
		Credential: orascredentials.Credential(store),
	}
	repo.PlainHTTP = imageRef.Context().Scheme() == "http"

	// Resolve the subject descriptor.
	subjectDesc, err := repo.Resolve(ctx, imageRef.Identifier())
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("ORAS: resolving subject: %w", err)
	}

	var found ocispec.Descriptor
	err = repo.Referrers(ctx, subjectDesc, mediaType, func(referrers []ocispec.Descriptor) error {
		for _, r := range referrers {
			at := r.ArtifactType
			if at == "" {
				at = r.MediaType
			}
			if at == mediaType {
				found = r
				return errStop
			}
		}
		return nil
	})
	if err != nil && err != errStop {
		return ocispec.Descriptor{}, fmt.Errorf("ORAS tag-based referrer discovery failed: %w", err)
	}
	if found.Digest.String() == "" {
		return ocispec.Descriptor{}, fmt.Errorf("no referrer with media type %q found (tag-based fallback)", mediaType)
	}
	return found, nil
}

// errStop is a sentinel used to stop ORAS iteration early.
var errStop = fmt.Errorf("stop")

// digestFromGCR converts a gcr digest to an OCI digest string.
func digestFromGCR(d interface{ String() string }) digest.Digest {
	return digest.Digest(d.String())
}
