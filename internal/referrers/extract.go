package referrers

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	gcrremote "github.com/google/go-containerregistry/pkg/v1/remote"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Extract pulls the referrer artifact described by desc from the registry and
// extracts its tar layer(s) into destDir.
func Extract(
	ctx context.Context,
	imageRef name.Reference,
	desc ocispec.Descriptor,
	destDir string,
	transport http.RoundTripper,
	keychain authn.Keychain,
) error {
	referrerRef, err := name.NewDigest(
		imageRef.Context().String() + "@" + string(desc.Digest),
	)
	if err != nil {
		return fmt.Errorf("building referrer digest ref: %w", err)
	}
	return ExtractByRef(ctx, referrerRef, destDir, transport, keychain)
}

// ExtractByRef pulls a standalone OCI image by reference and extracts its tar
// layer(s) into destDir. Use this when the bundle is not attached as a referrer
// but stored as a regular image at a known reference.
func ExtractByRef(
	ctx context.Context,
	ref name.Reference,
	destDir string,
	transport http.RoundTripper,
	keychain authn.Keychain,
) error {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("creating extract dir %s: %w", destDir, err)
	}

	gcrOpts := []gcrremote.Option{
		gcrremote.WithContext(ctx),
		gcrremote.WithAuthFromKeychain(keychain),
		gcrremote.WithTransport(transport),
	}

	// Fetch the image so we can access its layers.
	img, err := gcrremote.Image(ref, gcrOpts...)
	if err != nil {
		return fmt.Errorf("fetching image: %w", err)
	}

	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("getting image layers: %w", err)
	}
	if len(layers) == 0 {
		return fmt.Errorf("image has no layers")
	}

	for i, layer := range layers {
		rc, err := layer.Uncompressed()
		if err != nil {
			return fmt.Errorf("decompressing layer %d: %w", i, err)
		}
		if err := extractTar(rc, destDir); err != nil {
			_ = rc.Close()
			return fmt.Errorf("extracting layer %d: %w", i, err)
		}
		if err := rc.Close(); err != nil {
			return fmt.Errorf("closing layer %d: %w", i, err)
		}
	}

	fmt.Fprintf(os.Stderr, "verify-cmp: extracted manifest bundle to %s\n", destDir)
	return nil
}

// extractTar reads a tar stream and writes each entry into destDir,
// guarding against path traversal attacks.
func extractTar(r io.Reader, destDir string) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar: %w", err)
		}

		// Guard against path traversal.
		target := filepath.Join(destDir, filepath.Clean("/"+hdr.Name))
		cleanDest := filepath.Clean(destDir)
		if target != cleanDest && !strings.HasPrefix(target, cleanDest+string(os.PathSeparator)) {
			return fmt.Errorf("tar entry %q would escape destination dir", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				_ = f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		}
	}
	return nil
}
