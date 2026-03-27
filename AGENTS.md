# ArgoCD OCI Signature Verification CMP

## Overview

A Config Management Plugin (CMP) sidecar for ArgoCD that verifies cosign signatures on OCI images and discovers Kubernetes manifest bundles via the OCI referrers API. Instead of maintaining a separate manifest repository, manifests are attached as referrers to the application image itself — keeping the image, its signature, SBOM, and deployment manifests together as a single signed unit. Designed for air-gapped environments with GitLab CI.

## OCI Artifact Model

```
registry.internal.example.com/my-app:v1.0.0
│
├── [image]     application/vnd.oci.image.manifest.v1+json    (app container)
├── [signature] application/vnd.dev.cosign.simplesigning.v1   (cosign signature)
├── [referrer]  text/spdx+json                                (SBOM)
└── [referrer]  application/vnd.acme.k8s-manifests.v1+tar     (K8s manifest bundle)
```

All artifacts share one OCI reference. The manifest bundle is discovered at sync time via the referrers API, not configured as a separate repo.

## Architecture

```
argocd-repo-server pod
├── repo-server container
└── verify-cmp sidecar
    ├── /var/run/argocd/argocd-cmp-server  (entrypoint, from shared vol)
    ├── /usr/local/bin/verify-cmp           (our binary)
    ├── /home/argocd/cmp-server/config/plugin.yaml
    └── /etc/verify-cmp/config.yaml
```

CMP `init`: verify cosign signature on OCI image → query referrers API → pull manifest bundle → extract to working dir.
CMP `generate`: output extracted manifests to stdout.

## Project Structure

```
argocd-verify-cmp/
├── cmd/
│   └── verify-cmp/
│       └── main.go              # CLI entrypoint (init / generate subcommands)
├── internal/
│   ├── config/
│   │   └── config.go            # Config loading and validation
│   ├── verify/
│   │   ├── verifier.go          # Verifier interface
│   │   ├── key.go               # Static public key verification
│   │   ├── kms.go               # KMS verification (Vault, AWS, GCP)
│   │   └── multi.go             # Multi-key support (rotation window)
│   ├── referrers/
│   │   ├── referrers.go         # Query OCI referrers API by media type
│   │   └── extract.go           # Pull referrer blob, extract tar to working dir
│   └── manifest/
│       └── manifest.go          # Walk dir, concat YAML/JSON, output to stdout
├── deploy/
│   ├── Containerfile            # Distroless/static base + verify-cmp binary
│   ├── plugin.yaml              # CMP plugin config
│   ├── kustomization.yaml       # Patch for argocd-repo-server
│   └── sidecar-patch.yaml       # Sidecar container + volume mounts
├── config.example.yaml          # Example configuration
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

## Configuration

```yaml
# config.yaml
verification:
  # "kms" or "key"
  mode: key

  key:
    # Primary public key path
    path: /etc/cosign/cosign.pub

  kms:
    # Hashicorp Vault, awskms://, gcpkms:// etc
    ref: hashicorp://vault/transit/keys/cosign

  # Additional keys accepted during rotation
  additionalKeys:
    - /etc/cosign/cosign-old.pub

  # Restrict to known internal registries
  allowedRegistries:
    - registry.internal.example.com

# OCI registry connection settings
registry:
  # Authentication: path to Docker config.json
  # cosign and ORAS use this automatically via the Docker credential chain
  # NOTE: ArgoCD's ASKPASS mechanism is git-only and does not work for OCI registries.
  # Use a mounted Secret with .dockerconfigjson instead.
  dockerConfigPath: /etc/docker/config.json

  # TLS settings
  tls:
    # Allow insecure (HTTP) connections to the registry (dev/testing only)
    insecure: false
    # Path to custom CA certificate bundle for the registry (PEM format)
    # Leave empty to use system CA pool
    caCertPath: /etc/verify-cmp/ca.crt
    # Skip TLS certificate verification (NOT recommended, even in air-gapped)
    skipVerify: false

# OCI referrers API settings
referrers:
  # Media type of the manifest bundle referrer
  manifestMediaType: application/vnd.acme.k8s-manifests.v1+tar
  # Directory to extract the manifest bundle into
  extractDir: /tmp/manifests
  # Fallback: if true, also try OCI tag-based referrers (pre OCI 1.1 registries)
  enableTagFallback: true

# Air-gapped settings
airgap:
  # Skip Rekor transparency log checks
  skipTlog: true
```

## Dependencies

Go modules:

- `github.com/sigstore/cosign/v2` — signature verification core
  - `pkg/cosign` — `VerifyImageSignatures()`
  - `pkg/cosign/pkcs11key` — static key loading
- `github.com/sigstore/sigstore/pkg/signature/kms` — KMS provider resolution
  - Auto-resolves `hashicorp://`, `awskms://`, `gcpkms://`
- `github.com/google/go-containerregistry` — OCI reference parsing and registry interaction
  - `name.ParseReference()` for `ARGOCD_APP_SOURCE_REPO_URL`
  - `remote.Referrers()` — query OCI referrers API (OCI 1.1)
  - `remote.Image()` / `remote.Layer()` — pull referrer blobs
- `oras.land/oras-go/v2` — alternative/fallback for referrers discovery
  - Handles both OCI 1.1 referrers API and tag-based fallback for older registries
- `gopkg.in/yaml.v3` — config parsing
- `github.com/spf13/cobra` — CLI subcommands (optional, can use bare os.Args)

## Plugin Activation

The plugin should only run for OCI sources. Two layers handle this:

**Layer 1 — Application-level (primary):** Only Applications with OCI sources reference the plugin. The repoURL points to the app image itself — manifests are discovered via referrers.

```yaml
# OCI source — uses the plugin, repoURL is the app image
spec:
  source:
    repoURL: oci://registry.internal.example.com/my-app
    targetRevision: v1.0.0
    path: overlays/production  # subdirectory within extracted bundle
    plugin:
      name: cosign-verified-manifests

# Git source — no plugin, normal ArgoCD flow
spec:
  source:
    repoURL: https://git.internal.example.com/team/manifests.git
```

**Layer 2 — init safety check (defensive):** If the plugin is accidentally attached to a non-OCI source, `init` checks `ARGOCD_APP_SOURCE_REPO_URL` for the `oci://` prefix. If absent, it logs a skip message to stderr and exits 0, becoming a passthrough. This prevents blocking non-OCI syncs.

## Implementation Notes

### ArgoCD CMP Environment Variables

ArgoCD injects these into the CMP sidecar:

- `ARGOCD_APP_SOURCE_REPO_URL` — OCI image reference (e.g. `oci://registry.internal.example.com/my-app`)
- `ARGOCD_APP_SOURCE_TARGET_REVISION` — tag or digest (e.g. `v1.0.0` or `sha256:abc...`)
- `ARGOCD_APP_SOURCE_PATH` — subdirectory within the extracted manifest bundle

### init command

1. Read `ARGOCD_APP_SOURCE_REPO_URL` env var
2. **If not `oci://` prefix → log skip to stderr, exit 0 (passthrough)**
3. Strip `oci://` prefix
4. Read `ARGOCD_APP_SOURCE_TARGET_REVISION`:
   - If `sha256:` prefix → append as digest (`ref@sha256:...`)
   - Otherwise → append as tag (`ref:tag`)
   - If empty → use as-is (latest)
5. Parse full reference with `go-containerregistry/pkg/name`
   - If `registry.tls.insecure: true` → use `name.Insecure` option (HTTP scheme)
6. Validate reference against `allowedRegistries` (reject if not matched)
7. **Configure registry transport (auth + TLS):**
   - Build `http.Transport` with TLS config from `registry.tls`
   - If `caCertPath` set → load PEM, append to `x509.CertPool`
   - If `skipVerify: true` → set `InsecureSkipVerify` (log warning)
   - If `insecure: true` → allow HTTP (plain) connections
   - Load Docker credentials from `registry.dockerConfigPath` via `authn.NewKeychainFromDockerConfig()`
   - Pass transport and keychain as `remote.Option` to all registry calls
8. **Verify cosign signature on the image:**
   - Build `cosign.CheckOpts` (key/KMS, IgnoreTlog, IgnoreSCT, RegistryClientOpts)
   - Call `cosign.VerifyImageSignatures(ctx, ref, checkOpts)`
   - If primary fails and `additionalKeys` exist, retry with each
   - Exit 1 if all verifiers fail
9. **Discover manifest bundle via OCI referrers API:**
   - Resolve image descriptor (`remote.Head()` or `remote.Image()`)
   - Call referrers API filtered by `referrers.manifestMediaType`
   - If OCI 1.1 referrers API fails and `enableTagFallback: true`, try tag-based fallback
   - Exit 1 if no manifest bundle referrer found
10. **Pull and extract the manifest bundle:**
    - Pull the referrer blob
    - Extract tar to `referrers.extractDir` (default `/tmp/manifests`)
11. Log all results to stderr (ArgoCD surfaces stderr in UI)

### Registry Authentication

ArgoCD's ASKPASS mechanism is git-only — it uses `GIT_ASKPASS` to retrieve credentials over a Unix socket between the CMP sidecar and the repo-server. This does not work for OCI registry authentication since cosign and ORAS use Docker's credential chain, not git's.

**Recommended approach:** Create a Kubernetes Secret with `.dockerconfigjson` for your internal registry and mount it into the CMP sidecar. Set `registry.dockerConfigPath` to point at it. Both cosign and ORAS resolve credentials automatically via `authn.DefaultKeychain`.

```yaml
# Secret for registry credentials
apiVersion: v1
kind: Secret
metadata:
  name: verify-cmp-registry-creds
  namespace: argocd
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: <base64-encoded>
```

```yaml
# Sidecar volume mount
volumeMounts:
  - name: registry-creds
    mountPath: /etc/docker
    readOnly: true
volumes:
  - name: registry-creds
    secret:
      secretName: verify-cmp-registry-creds
      items:
        - key: .dockerconfigjson
          path: config.json
```

### Registry TLS

In air-gapped environments, internal registries often use private CA certificates or self-signed certs.

**Implementation:** Build a custom `http.Transport` shared across all registry calls (cosign verify, referrers discovery, blob pull).

```go
func buildTransport(cfg Config) (*http.Transport, error) {
    transport := http.DefaultTransport.(*http.Transport).Clone()

    tlsCfg := &tls.Config{}

    // Custom CA certificate
    if cfg.Registry.TLS.CACertPath != "" {
        caCert, err := os.ReadFile(cfg.Registry.TLS.CACertPath)
        if err != nil {
            return nil, fmt.Errorf("reading CA cert: %w", err)
        }
        pool, err := x509.SystemCertPool()
        if err != nil {
            pool = x509.NewCertPool()
        }
        pool.AppendCertsFromPEM(caCert)
        tlsCfg.RootCAs = pool
    }

    // Skip TLS verification (not recommended)
    if cfg.Registry.TLS.SkipVerify {
        logInfo("WARNING: TLS verification disabled")
        tlsCfg.InsecureSkipVerify = true
    }

    transport.TLSClientConfig = tlsCfg
    return transport, nil
}
```

Mount the CA cert from a ConfigMap or Secret:

```yaml
volumeMounts:
  - name: registry-ca
    mountPath: /etc/verify-cmp/ca.crt
    subPath: ca.crt
    readOnly: true
volumes:
  - name: registry-ca
    configMap:
      name: verify-cmp-registry-ca
```

### generate command

1. Read `referrers.extractDir` as base directory (where init extracted the bundle)
2. If `ARGOCD_APP_SOURCE_PATH` is set, append it to base directory
3. Walk resulting directory for `*.yaml`, `*.yml`, `*.json` files
4. Skip hidden files/dirs
5. Read each file, concatenate with `---\n` separator
6. Print to stdout
7. Exit 1 if no manifests found

### multi-key rotation

```
Verifier interface {
    Verify(ctx, ref) ([]oci.Signature, error)
}

MultiVerifier holds []Verifier
  → tries each in order
  → returns success on first pass
  → returns aggregated error if all fail
```

### Error handling

- Config missing/invalid → exit 1 with clear message to stderr
- OCI ref not in allowedRegistries → exit 1, log which registry was rejected
- Registry auth failed (401/403) → exit 1, log hint to check dockerConfigPath and credentials Secret
- CA cert not found or invalid PEM → exit 1, log path that was attempted
- TLS handshake failed → exit 1, log cert details to help diagnose CA mismatch
- Signature verification failed → exit 1, log cosign error details
- Referrers API failed (and tag fallback also failed) → exit 1, log registry response
- No manifest bundle referrer found for configured media type → exit 1, log available referrers
- Manifest bundle extraction failed (bad tar, permissions) → exit 1
- No manifests in extract dir → exit 1 from generate
- KMS unreachable → exit 1, log connection error (important for Vault troubleshooting)

## Code Style

### Comments

Do not use decorative separator comments with dashes or box-drawing characters (e.g. `# ── Section ───────`). Use plain comments instead:

```bash
# Good
# OCI helpers

# Bad
# ── OCI helpers ───────────────────────────────────────────────────────────────
```

## Version Control

This project uses [Jujutsu (jj)](https://github.com/jj-vcs/jj) as its VCS. Use `jj` commands instead of `git` for all version control operations.

- **Small changes:** record with `jj new -m "<conventional commit message>"` (e.g. `feat:`, `fix:`, `chore:`, `refactor:`)
- **Large changes or experimentation:** use `jj workspace add` to create an isolated workspace

## Deployment

### Containerfile

```dockerfile
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /verify-cmp ./cmd/verify-cmp/

FROM cgr.dev/chainguard/static:latest
COPY --from=builder /verify-cmp /usr/local/bin/verify-cmp
COPY deploy/plugin.yaml /home/argocd/cmp-server/config/plugin.yaml
USER 999
```

### plugin.yaml

```yaml
apiVersion: argoproj.io/v1alpha1
kind: ConfigManagementPlugin
metadata:
  name: cosign-verified-manifests
spec:
  version: v1.0
  init:
    command: [/usr/local/bin/verify-cmp, init]
  generate:
    command: [/usr/local/bin/verify-cmp, generate]
  discover:
    fileName: "*.yaml"
```

### Sidecar patch

```yaml
# Patch argocd-repo-server deployment
spec:
  template:
    spec:
      containers:
        - name: cosign-verified-manifests
          image: registry.internal.example.com/verify-cmp:v1.0.0
          command: [/var/run/argocd/argocd-cmp-server]
          env:
            - name: VERIFY_CMP_CONFIG
              value: /etc/verify-cmp/config.yaml
            - name: DOCKER_CONFIG
              value: /etc/docker
          securityContext:
            runAsNonRoot: true
            runAsUser: 999
          volumeMounts:
            - name: var-files
              mountPath: /var/run/argocd
            - name: plugins
              mountPath: /home/argocd/cmp-server/plugins
            - name: cmp-tmp
              mountPath: /tmp
            - name: cosign-pub-key
              mountPath: /etc/cosign
              readOnly: true
            - name: verify-cmp-config
              mountPath: /etc/verify-cmp
              readOnly: true
            - name: registry-creds
              mountPath: /etc/docker
              readOnly: true
            - name: registry-ca
              mountPath: /etc/verify-cmp/ca.crt
              subPath: ca.crt
              readOnly: true
      volumes:
        - name: cosign-pub-key
          secret:
            secretName: cosign-pub-key
        - name: verify-cmp-config
          configMap:
            name: verify-cmp-config
        - name: registry-creds
          secret:
            secretName: verify-cmp-registry-creds
            items:
              - key: .dockerconfigjson
                path: config.json
        - name: registry-ca
          configMap:
            name: verify-cmp-registry-ca
            optional: true  # Not needed if using public CA or insecure mode
        - name: cmp-tmp
          emptyDir: {}
```

## Testing

### Unit tests
- `internal/verify/` — mock cosign verification, test multi-key fallback, test registry allowlist
- `internal/referrers/` — mock referrers API responses, test media type filtering, test tag fallback, test tar extraction
- `internal/config/` — test config parsing, defaults, validation
- `internal/manifest/` — test YAML/JSON concatenation, path handling, skip logic

### Integration tests
- Spin up local OCI registry (e.g. `zot` — supports OCI 1.1 referrers natively)
- Push image + sign with cosign → verify signature passes
- Push unsigned image → verify init exits 1
- Push image signed with old key → verify additionalKeys fallback works
- Push image from disallowed registry → verify rejection
- Attach manifest bundle as referrer with correct media type → verify discovery and extraction
- Attach manifest bundle with wrong media type → verify init exits 1 (not found)
- Test tag-based referrer fallback with `distribution` registry (pre OCI 1.1)
- Registry with auth enabled → verify credentials from dockerConfigPath are used
- Registry with no credentials mounted → verify clear 401 error message
- Registry with self-signed cert + caCertPath → verify TLS succeeds
- Registry with self-signed cert + no caCertPath → verify TLS error with helpful message
- Registry with `insecure: true` → verify HTTP connection works
- Registry with `skipVerify: true` → verify warning is logged

### E2E
- Deploy to test cluster with ArgoCD
- Create Application pointing to signed image with manifest referrer → sync succeeds, correct manifests applied
- Create Application pointing to unsigned image → sync fails with clear error in UI
- Create Application pointing to signed image without manifest referrer → sync fails with clear error

### CI pipeline test fixture
```bash
# Build and push app image
docker build -t registry.internal.example.com/my-app:v1.0.0 .
docker push registry.internal.example.com/my-app:v1.0.0

# Sign the image
cosign sign --key cosign.key registry.internal.example.com/my-app:v1.0.0

# Package and attach manifest bundle as referrer
tar cf manifests.tar -C deploy/ .
oras attach registry.internal.example.com/my-app:v1.0.0 \
  --artifact-type application/vnd.acme.k8s-manifests.v1+tar \
  manifests.tar
```

## Sign the CMP image itself

```bash
# In GitLab CI
cosign sign --key <key> registry.internal.example.com/verify-cmp:v1.0.0
```

Verify the verifier.
