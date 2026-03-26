# argocd-verify-cmp

An [ArgoCD Config Management Plugin (CMP)](https://argo-cd.readthedocs.io/en/stable/operator-manual/config-management-plugins/) that verifies [cosign](https://github.com/sigstore/cosign) signatures on OCI artifacts and extracts Kubernetes manifests for deployment.

## Overview

`verify-cmp` acts as a security gate in ArgoCD's GitOps pipeline. When ArgoCD syncs an application whose source is an OCI image reference, this plugin:

1. **Init phase** — Verifies the cosign signature on the referenced OCI image and extracts the manifest bundle to disk.
2. **Generate phase** — Outputs the extracted Kubernetes manifests to stdout for ArgoCD to apply.

Two artifact patterns are supported:

- **Referrer model** — An application image is signed, with a separate manifest bundle attached as an OCI referrer.
- **Standalone model** — A manifest bundle is stored as a complete OCI image with its own cosign signature.

## Configuration

The plugin is configured via a YAML file (default: `/etc/verify-cmp/config.yaml`, overridden by `VERIFY_CMP_CONFIG`).

```yaml
verification:
  mode: key          # "key", "kms", or "cert"
  key:
    path: /etc/verify-cmp/cosign.pub
  additionalKeys:    # optional — for key rotation
    - /etc/verify-cmp/cosign-secondary.pub
  allowedRegistries: # optional — registry allowlist
    - registry.example.com

registry:
  dockerConfigPath: /home/argocd/.docker/config.json
  tls:
    insecure: false
    caCertPath: ""
    skipVerify: false

referrers:
  manifestMediaType: application/vnd.acme.k8s-manifests.v1+tar
  extractDir: /tmp/manifests
  enableTagFallback: false   # enable for pre-OCI-1.1 registries

airgap:
  skipTlog: false            # set true to skip Rekor transparency log
  tufRoot: ""
```

**KMS mode** (AWS KMS, GCP KMS, or HashiCorp Vault) is selected by setting `verification.mode: kms` and providing a KMS key reference in `verification.kms.ref`.

**Certificate mode** verifies signatures against a regular X.509 certificate chain. Set `verification.mode: cert` and provide the root CA. If the signing certificate was issued by an intermediate CA, also supply the intermediate chain so cosign can validate the full path to the root:

```yaml
verification:
  mode: cert
  cert:
    path: /etc/verify-cmp/root-ca.pem
    intermediateCertsPath: /etc/verify-cmp/intermediates.pem  # optional
    identities:                                               # optional
      - subject: ci-bot@example.com
        issuer: https://accounts.google.com
      - subjectRegExp: "https://github.com/my-org/.*"
        issuer: https://token.actions.githubusercontent.com
```

`identities` constrains which certificate subjects and issuers are accepted. Each entry may use literal `subject`/`issuer` fields or the `subjectRegExp`/`issuerRegExp` variants. When omitted, any certificate that chains to the root CA is accepted.

See `config.example.yaml` for a fully annotated example.

### ArgoCD Environment Variables

ArgoCD injects these automatically — no manual configuration needed:

| Variable | Description |
|---|---|
| `ARGOCD_APP_SOURCE_REPO_URL` | OCI image reference |
| `ARGOCD_APP_SOURCE_TARGET_REVISION` | Image tag or digest |
| `ARGOCD_APP_SOURCE_PATH` | Optional subpath for manifest filtering |

Non-OCI sources (e.g. `git://`) are passed through without verification.

## Installation

### Building from source

```bash
make build
# Output: bin/verify-cmp
```

### Building the container image

```bash
make docker
```

The Dockerfile uses a multi-stage build: a `golang:1.26-alpine` builder followed by a minimal `cgr.dev/chainguard/static` runtime image. The binary runs as non-root (UID 999).

### Deploying to ArgoCD

Install `verify-cmp` as a sidecar to the ArgoCD repo-server using the CMP sidecar pattern. Mount the container image alongside a `plugin.yaml` that declares the `init` and `generate` commands:

```yaml
# deploy/plugin.yaml (included at /home/argocd/cmp-server/config/plugin.yaml in the image)
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

Mount your cosign public key and a config file into the sidecar at the paths referenced by `config.example.yaml`.

### Referencing the plugin from an Application

Set `spec.source.plugin` on your ArgoCD `Application` to select the plugin by name and version:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: my-app
  namespace: argocd
spec:
  source:
    repoURL: oci://registry.example.com/my-app
    targetRevision: "1.2.3"
    plugin:
      name: cosign-verified-manifests
      version: v1.0
  destination:
    server: https://kubernetes.default.svc
    namespace: my-app
  project: default
```

The `repoURL` and `targetRevision` fields are passed to the plugin as `ARGOCD_APP_SOURCE_REPO_URL` and `ARGOCD_APP_SOURCE_TARGET_REVISION` respectively. To scope manifests to a subdirectory within the bundle, also set `spec.source.path`.

## Development

### Prerequisites

- Go 1.25+
- `cosign` and `oras` CLIs
- Docker or Podman (for integration tests)

With [Nix](https://nixos.org/):
```bash
nix develop
```

### Running tests

```bash
make test             # unit tests
make lint             # golangci-lint
make integration-test # full integration suite (setup → run → teardown)
```

The integration test suite spins up a local [Zot](https://zotregistry.dev/) OCI registry and runs scenarios covering: signed referrers, standalone bundles, key rotation, registry allowlisting, subpath scoping, and invalid auth rejection.
