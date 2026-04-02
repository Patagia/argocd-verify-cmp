# argocd-verify-cmp

> **Work in progress.** This plugin depends on `spec.fetch` and related CMP extensions that are not yet in upstream ArgoCD. It currently targets the [Patagia ArgoCD fork](https://github.com/Patagia/argo-cd). The API may change as these features are developed and upstreamed.

An [ArgoCD Config Management Plugin (CMP)](https://argo-cd.readthedocs.io/en/stable/operator-manual/config-management-plugins/) that verifies [cosign](https://github.com/sigstore/cosign) signatures on OCI artifacts and extracts Kubernetes manifests for deployment.

## Overview

`verify-cmp` acts as a security gate in ArgoCD's GitOps pipeline. When ArgoCD syncs an application whose source is an OCI image reference, this plugin:

1. **Fetch phase** — Verifies the cosign signature on the referenced OCI image, extracts the manifest bundle to disk, and writes `.argocd-cmp-fetch-result.json` with the resolved content digest and verification result for ArgoCD to surface in the UI.
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
  additional:        # optional — OR chain: any of these also accepted
    - mode: key
      key:
        path: /etc/verify-cmp/cosign-secondary.pub
  required:          # optional — AND chain: all of these must also have signed
    - mode: key
      key:
        path: /etc/verify-cmp/internal-blessing.pub
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

**Attestation mode** verifies that a signed cosign attestation (`cosign attest`) with a specific `predicateType` is attached. Optionally asserts top-level predicate fields via `claims`. Attestation verifiers can appear in `additional` (OR chain) or `required` (AND chain) and support all signing modes (`key`, `kms`, `cert`):

```yaml
verification:
  mode: key
  key:
    path: /etc/verify-cmp/upstream.pub
  required:
    - mode: attestation
      attestation:
        predicateType: https://example.com/internal-blessing/v1
        signingMode: key
        key:
          path: /etc/verify-cmp/internal-blessing.pub
        claims:             # optional — assert top-level predicate fields
          approved: "true"
          reviewer: ci-bot@example.com
```

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

### Deploying to ArgoCD

Install `verify-cmp` as a sidecar to the ArgoCD repo-server using the CMP sidecar pattern. Mount the container image alongside a `plugin.yaml` that declares the `fetch` and `generate` commands:

```yaml
# deploy/plugin.yaml (included at /home/argocd/cmp-server/config/plugin.yaml in the image)
apiVersion: argoproj.io/v1alpha1
kind: ConfigManagementPlugin
metadata:
  name: cosign-verified-manifests
spec:
  version: v1.0
  fetch:
    command: [/usr/local/bin/verify-cmp, fetch]
  generate:
    command: [/usr/local/bin/verify-cmp, generate]
```

This plugin uses `spec.fetch` (available in the Patagia ArgoCD fork) rather than `spec.init`. With `spec.fetch`, ArgoCD delegates source retrieval entirely to the plugin and reads back the resolved revision and verification output from `.argocd-cmp-fetch-result.json`. Because the plugin is explicitly referenced by name in each Application, `spec.discover` is not needed.

Mount your cosign public key and a config file into the sidecar at the paths referenced by `config.example.yaml`.

### Referencing the plugin from an Application

Set `spec.source.plugin` on your ArgoCD `Application` to select the plugin by name:

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
  destination:
    server: https://kubernetes.default.svc
    namespace: my-app
  project: default
```

The `repoURL` and `targetRevision` fields are passed to the plugin as `ARGOCD_APP_SOURCE_REPO_URL` and `ARGOCD_APP_SOURCE_TARGET_REVISION` respectively. To scope manifests to a subdirectory within the bundle, also set `spec.source.path`.

## Development

### Prerequisites

- Go 1.26+
- `cosign` and `oras` CLIs

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
