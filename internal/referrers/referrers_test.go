package referrers_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	gcrregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	gcrremote "github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/Patagia/argocd-verify-cmp/internal/referrers"
)

const (
	testBundleMediaType = "application/vnd.test.k8s-manifests.v1+tar"
	otherMediaType      = "application/vnd.test.other.v1+json"
)

// anonKeychain is a Keychain that always returns anonymous credentials.
var anonKeychain authn.Keychain = anonymousKeychain{}

type anonymousKeychain struct{}

func (anonymousKeychain) Resolve(authn.Resource) (authn.Authenticator, error) {
	return authn.Anonymous, nil
}

// registry helpers

func startRegistry(t *testing.T, withReferrers bool) *httptest.Server {
	t.Helper()
	var opts []gcrregistry.Option
	if withReferrers {
		opts = append(opts, gcrregistry.WithReferrersSupport(true))
	}
	s := httptest.NewServer(gcrregistry.New(opts...))
	t.Cleanup(s.Close)
	return s
}

// regRef parses a reference against the test registry host.
func regRef(t *testing.T, s *httptest.Server, repoAndRef string) name.Reference {
	t.Helper()
	host := strings.TrimPrefix(s.URL, "http://")
	ref, err := name.ParseReference(host+"/"+repoAndRef, name.Insecure)
	if err != nil {
		t.Fatalf("parsing reference %q: %v", repoAndRef, err)
	}
	return ref
}

func gcrOpts(s *httptest.Server) []gcrremote.Option {
	return []gcrremote.Option{
		gcrremote.WithAuthFromKeychain(anonKeychain),
		gcrremote.WithTransport(http.DefaultTransport),
	}
}

// push helpers

// pushImage pushes a minimal empty OCI image and returns (digest, raw manifest bytes).
func pushImage(t *testing.T, s *httptest.Server, repo, tag string) (v1.Hash, []byte) {
	t.Helper()
	ref := regRef(t, s, repo+":"+tag)
	img := empty.Image
	if err := gcrremote.Write(ref, img, gcrOpts(s)...); err != nil {
		t.Fatalf("pushing image: %v", err)
	}
	raw, err := img.RawManifest()
	if err != nil {
		t.Fatalf("raw manifest: %v", err)
	}
	d, err := img.Digest()
	if err != nil {
		t.Fatalf("image digest: %v", err)
	}
	return d, raw
}

// hexSHA256 returns the hex-encoded SHA256 of b (no "sha256:" prefix).
func hexSHA256(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// pushBlob pushes a raw blob and returns its "sha256:<hex>" digest string.
func pushBlob(t *testing.T, s *httptest.Server, repo string, content []byte) string {
	t.Helper()
	dig := "sha256:" + hexSHA256(content)

	resp, err := s.Client().Post(s.URL+"/v2/"+repo+"/blobs/uploads/", "", nil)
	if err != nil {
		t.Fatalf("initiating blob upload: %v", err)
	}
	_ = resp.Body.Close()

	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "http") {
		loc = s.URL + loc
	}
	sep := "?"
	if strings.Contains(loc, "?") {
		sep = "&"
	}
	loc += sep + "digest=" + url.QueryEscape(dig)

	req, _ := http.NewRequest(http.MethodPut, loc, bytes.NewReader(content))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = int64(len(content))
	resp, err = s.Client().Do(req)
	if err != nil {
		t.Fatalf("putting blob: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("putting blob %s: status %d", dig, resp.StatusCode)
	}
	return dig
}

// putManifestBytes PUTs a manifest JSON to the registry under ref (tag or digest).
func putManifestBytes(t *testing.T, s *httptest.Server, repo, ref string, manifestBytes []byte) {
	t.Helper()
	u := s.URL + "/v2/" + repo + "/manifests/" + ref
	req, _ := http.NewRequest(http.MethodPut, u, bytes.NewReader(manifestBytes))
	req.Header.Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
	req.ContentLength = int64(len(manifestBytes))
	resp, err := s.Client().Do(req)
	if err != nil {
		t.Fatalf("putting manifest: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("putting manifest %q: status %d", ref, resp.StatusCode)
	}
}

type ociDescriptor struct {
	MediaType    string `json:"mediaType"`
	Digest       string `json:"digest"`
	Size         int64  `json:"size"`
	ArtifactType string `json:"artifactType,omitempty"`
}

type ociManifest struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	ArtifactType  string          `json:"artifactType,omitempty"`
	Config        ociDescriptor   `json:"config"`
	Layers        []ociDescriptor `json:"layers"`
	Subject       *ociDescriptor  `json:"subject,omitempty"`
}

// buildAndPushArtifact pushes an OCI artifact manifest with the given artifactType.
// If subject is non-nil the manifest will reference it (making this a referrer).
// Returns the raw manifest bytes.
func buildAndPushArtifact(t *testing.T, s *httptest.Server, repo string, artifactType string, subject *ociDescriptor, tarContent []byte) []byte {
	t.Helper()

	emptyConfig := []byte("{}")
	configDig := pushBlob(t, s, repo, emptyConfig)
	layerDig := pushBlob(t, s, repo, tarContent)

	// The gcr in-memory registry builds the referrers descriptor ArtifactType
	// from config.mediaType (not the top-level artifactType field). Set both so
	// the registry's filtering and our Find() filtering both work.
	m := ociManifest{
		SchemaVersion: 2,
		MediaType:     "application/vnd.oci.image.manifest.v1+json",
		ArtifactType:  artifactType,
		Config:        ociDescriptor{MediaType: artifactType, Digest: configDig, Size: int64(len(emptyConfig))},
		Layers:        []ociDescriptor{{MediaType: "application/vnd.oci.image.layer.v1.tar", Digest: layerDig, Size: int64(len(tarContent))}},
		Subject:       subject,
	}
	manifestBytes, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshaling manifest: %v", err)
	}

	// Push by digest so the registry stores it (required for referrers API lookup).
	putManifestBytes(t, s, repo, "sha256:"+hexSHA256(manifestBytes), manifestBytes)
	return manifestBytes
}

// smallTar returns a minimal tar archive with one YAML file.
func smallTar(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	content := []byte("kind: Deployment\n")
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "deploy.yaml", Size: int64(len(content)), Mode: 0o644}) //nolint:errcheck
	tw.Write(content)                                                                                                 //nolint:errcheck
	tw.Close()                                                                                                        //nolint:errcheck
	return buf.Bytes()
}

// ArtifactType tests

func TestArtifactType_ContainerImage(t *testing.T) {
	s := startRegistry(t, false)
	imgDigest, _ := pushImage(t, s, "myrepo", "v1")
	ref := regRef(t, s, "myrepo@"+imgDigest.String())

	at, err := referrers.ArtifactType(context.Background(), ref, http.DefaultTransport, anonKeychain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if at != "" {
		t.Errorf("expected empty artifactType for container image, got %q", at)
	}
}

func TestArtifactType_BundleArtifact(t *testing.T) {
	s := startRegistry(t, false)
	// Push a standalone artifact (no subject) — this IS the bundle.
	manifestBytes := buildAndPushArtifact(t, s, "myrepo", testBundleMediaType, nil, smallTar(t))
	ref := regRef(t, s, "myrepo@sha256:"+hexSHA256(manifestBytes))

	at, err := referrers.ArtifactType(context.Background(), ref, http.DefaultTransport, anonKeychain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if at != testBundleMediaType {
		t.Errorf("artifactType = %q, want %q", at, testBundleMediaType)
	}
}

func TestArtifactType_NotFound(t *testing.T) {
	s := startRegistry(t, false)
	ref := regRef(t, s, "myrepo:nonexistent")

	_, err := referrers.ArtifactType(context.Background(), ref, http.DefaultTransport, anonKeychain)
	if err == nil {
		t.Fatal("expected error for non-existent image, got nil")
	}
}

// Find tests

func TestFind_OCI11_Discovers(t *testing.T) {
	s := startRegistry(t, true)
	imgDigest, imgRaw := pushImage(t, s, "myrepo", "v1")
	subjectDesc := &ociDescriptor{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Digest:    imgDigest.String(),
		Size:      int64(len(imgRaw)),
	}
	buildAndPushArtifact(t, s, "myrepo", testBundleMediaType, subjectDesc, smallTar(t))

	ref := regRef(t, s, "myrepo:v1")
	desc, err := referrers.Find(
		context.Background(), ref,
		testBundleMediaType, false,
		http.DefaultTransport, anonKeychain, "",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if desc.ArtifactType != testBundleMediaType {
		t.Errorf("artifactType = %q, want %q", desc.ArtifactType, testBundleMediaType)
	}
}

func TestFind_OCI11_MediaTypeFiltering(t *testing.T) {
	s := startRegistry(t, true)
	imgDigest, imgRaw := pushImage(t, s, "myrepo", "v1")
	subjectDesc := &ociDescriptor{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Digest:    imgDigest.String(),
		Size:      int64(len(imgRaw)),
	}
	tar := smallTar(t)
	buildAndPushArtifact(t, s, "myrepo", testBundleMediaType, subjectDesc, tar)
	buildAndPushArtifact(t, s, "myrepo", otherMediaType, subjectDesc, tar)

	ref := regRef(t, s, "myrepo:v1")
	desc, err := referrers.Find(
		context.Background(), ref,
		testBundleMediaType, false,
		http.DefaultTransport, anonKeychain, "",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if desc.ArtifactType != testBundleMediaType {
		t.Errorf("artifactType = %q, want %q", desc.ArtifactType, testBundleMediaType)
	}
}

func TestFind_OCI11_NoMatchingReferrer(t *testing.T) {
	s := startRegistry(t, true)
	imgDigest, imgRaw := pushImage(t, s, "myrepo", "v1")
	subjectDesc := &ociDescriptor{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Digest:    imgDigest.String(),
		Size:      int64(len(imgRaw)),
	}
	buildAndPushArtifact(t, s, "myrepo", otherMediaType, subjectDesc, smallTar(t))

	ref := regRef(t, s, "myrepo:v1")
	_, err := referrers.Find(
		context.Background(), ref,
		testBundleMediaType, false,
		http.DefaultTransport, anonKeychain, "",
	)
	if err == nil {
		t.Fatal("expected error when no referrer matches media type, got nil")
	}
}

func TestFind_OCI11_MultipleMatchingReferrers(t *testing.T) {
	// Two referrers share the same media type — Find should succeed and return
	// one of them without error (a warning is emitted to stderr).
	s := startRegistry(t, true)
	imgDigest, imgRaw := pushImage(t, s, "myrepo", "v1")
	subjectDesc := &ociDescriptor{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Digest:    imgDigest.String(),
		Size:      int64(len(imgRaw)),
	}
	buildAndPushArtifact(t, s, "myrepo", testBundleMediaType, subjectDesc, smallTar(t))
	buildAndPushArtifact(t, s, "myrepo", testBundleMediaType, subjectDesc, smallTar(t))

	ref := regRef(t, s, "myrepo:v1")
	desc, err := referrers.Find(
		context.Background(), ref,
		testBundleMediaType, false,
		http.DefaultTransport, anonKeychain, "",
	)
	if err != nil {
		t.Fatalf("unexpected error with multiple matching referrers: %v", err)
	}
	if desc.ArtifactType != testBundleMediaType {
		t.Errorf("artifactType = %q, want %q", desc.ArtifactType, testBundleMediaType)
	}
}

func TestFind_ReferrersAPIUnsupported_FallbackDisabled(t *testing.T) {
	// Registry without OCI 1.1 referrers API; fallback disabled → must error.
	s := startRegistry(t, false)
	pushImage(t, s, "myrepo", "v1")

	ref := regRef(t, s, "myrepo:v1")
	_, err := referrers.Find(
		context.Background(), ref,
		testBundleMediaType, false,
		http.DefaultTransport, anonKeychain, "",
	)
	if err == nil {
		t.Fatal("expected error when referrers API unsupported and fallback disabled, got nil")
	}
}
