#!/usr/bin/env bash
# helpers.bash — BATS helper functions for integration tests.
# Loaded automatically by integration.bats via: load helpers

HELPERS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HELPERS_DIR/../.." && pwd)"

REGISTRY="localhost:5000"
REGISTRY_USER="testuser"
REGISTRY_PASS="testpass"
BINARY="$REPO_ROOT/bin/verify-cmp"
FIXTURES="$HELPERS_DIR/fixtures"

export DOCKER_CONFIG="$FIXTURES/auth"

# OCI helpers

# push_image REPO TAG — push a minimal OCI image (no artifactType).
push_image() {
  local repo=$1 tag=$2
  local cfg; cfg="$(mktemp)"
  echo '{}' > "$cfg"
  oras push "$REGISTRY/$repo:$tag" \
    --config "$cfg:application/vnd.oci.image.config.v1+json" \
    --plain-http \
    --disable-path-validation 2>/dev/null
  rm -f "$cfg"
}

# push_bundle REPO TAG — push a standalone bundle artifact.
push_bundle() {
  local repo=$1 tag=$2
  local bundle; bundle="$(mktemp)"
  tar cf "$bundle" -C "$FIXTURES/manifests" . 2>/dev/null
  oras push "$REGISTRY/$repo:$tag" \
    --artifact-type "application/vnd.test.k8s-manifests.v1+tar" \
    --plain-http \
    --disable-path-validation \
    "$bundle:application/vnd.oci.image.layer.v1.tar" 2>/dev/null
  rm -f "$bundle"
}

# sign REPO TAG [KEY_PATH] — cosign sign with no Rekor, no SCT.
sign() {
  local repo=$1 tag=$2 key=${3:-"$FIXTURES/cosign.key"}
  COSIGN_PASSWORD="" cosign sign \
    --key "$key" \
    --signing-config "$FIXTURES/signing-config.json" \
    --allow-insecure-registry \
    "$REGISTRY/$repo:$tag" 2>/dev/null
}

# attach_bundle REPO TAG [ARTIFACT_TYPE] — attach manifest tar as an OCI referrer.
attach_bundle() {
  local repo=$1 tag=$2 atype=${3:-"application/vnd.test.k8s-manifests.v1+tar"}
  local bundle; bundle="$(mktemp)"
  tar cf "$bundle" -C "$FIXTURES/manifests" . 2>/dev/null
  oras attach "$REGISTRY/$repo:$tag" \
    --artifact-type "$atype" \
    --plain-http \
    --disable-path-validation \
    "$bundle:application/vnd.oci.image.layer.v1.tar" 2>/dev/null
  rm -f "$bundle"
}

# verify-cmp helpers

# run_init REPO TAG CONFIG — invoke verify-cmp init directly.
run_init() {
  local repo=$1 tag=$2 config=$3
  ARGOCD_APP_SOURCE_REPO_URL="oci://$REGISTRY/$repo" \
  ARGOCD_APP_SOURCE_TARGET_REVISION="$tag" \
  VERIFY_CMP_CONFIG="$config" \
    "$BINARY" init
}

# run_generate CONFIG [SUBPATH] — invoke verify-cmp generate, print stdout.
run_generate() {
  local config=$1 subpath=${2:-""}
  VERIFY_CMP_CONFIG="$config" \
  ARGOCD_APP_SOURCE_PATH="$subpath" \
    "$BINARY" generate
}
