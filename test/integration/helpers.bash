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
TESTENV="$HELPERS_DIR/.testenv"
# WORKDIR simulates the per-request temp dir ArgoCD creates for each sync.
# Both fetch and generate run here so relative paths (e.g. extractDir: manifests)
# resolve consistently between the two commands.
WORKDIR="$TESTENV/workdir"

export DOCKER_CONFIG="$TESTENV/auth"

# OCI helpers

# push_image REPO TAG — push a minimal OCI image with standard OCI annotations.
push_image() {
  local repo=$1 tag=$2
  local cfg; cfg="$(mktemp)"
  local created; created="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo '{}' > "$cfg"
  oras push "$REGISTRY/$repo:$tag" \
    --config "$cfg:application/vnd.oci.image.config.v1+json" \
    --plain-http \
    --disable-path-validation \
    --annotation "org.opencontainers.image.version=test-${tag}" \
    --annotation "org.opencontainers.image.authors=Test Author <test@example.com>" \
    --annotation "org.opencontainers.image.source=https://github.com/Patagia/argocd-verify-cmp" \
    --annotation "org.opencontainers.image.revision=abc1234567890abcdef1234567890abcdef123456" \
    --annotation "org.opencontainers.image.description=Test app image for argocd-verify-cmp integration tests" \
    --annotation "org.opencontainers.image.created=${created}" \
    2>/dev/null
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
  local repo=$1 tag=$2 key=${3:-"$TESTENV/cosign.key"}
  COSIGN_PASSWORD="" cosign sign \
    --key "$key" \
    --signing-config "$TESTENV/signing-config.json" \
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

# attest REPO TAG [KEY_PATH] [PREDICATE_TYPE] [PREDICATE_JSON]
# cosign attest with custom predicate and no Rekor.
attest() {
  local repo=$1 tag=$2 key=${3:-"$TESTENV/cosign.key"}
  local pred_type=${4:-"https://example.com/blessing/v1"}
  local pred_json=${5:-'{"approved":true}'}
  local pred_file; pred_file="$(mktemp)"
  echo "$pred_json" > "$pred_file"
  COSIGN_PASSWORD="" cosign attest \
    --key "$key" \
    --signing-config "$TESTENV/signing-config.json" \
    --predicate "$pred_file" \
    --type "$pred_type" \
    --allow-insecure-registry \
    "$REGISTRY/$repo:$tag" 2>/dev/null
  rm -f "$pred_file"
}

# verify-cmp helpers

# run_fetch REPO TAG CONFIG — invoke verify-cmp fetch from WORKDIR, simulating
# the per-request temp dir ArgoCD provides.
run_fetch() {
  local repo=$1 tag=$2 config=$3
  (cd "$WORKDIR" && \
    ARGOCD_APP_SOURCE_REPO_URL="oci://$REGISTRY/$repo" \
    ARGOCD_APP_SOURCE_TARGET_REVISION="$tag" \
    VERIFY_CMP_CONFIG="$config" \
      "$BINARY" fetch)
}

# run_generate CONFIG [SUBPATH] — invoke verify-cmp generate from WORKDIR.
run_generate() {
  local config=$1 subpath=${2:-""}
  (cd "$WORKDIR" && \
    VERIFY_CMP_CONFIG="$config" \
    ARGOCD_APP_SOURCE_PATH="$subpath" \
      "$BINARY" generate)
}
