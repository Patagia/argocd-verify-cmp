#!/usr/bin/env bats

bats_load_library bats-support
bats_load_library bats-assert
load helpers

CFG="$TESTENV/config.gen.yaml"
CFG_BAD_AUTH="$TESTENV/config-bad-auth.gen.yaml"
CFG_ADDL_KEYS="$TESTENV/config-additional-keys.gen.yaml"
CFG_DISALLOWED="$TESTENV/config-disallowed.gen.yaml"
CFG_ATTESTATION="$TESTENV/config-attestation.gen.yaml"
CFG_ATTESTATION_CLAIMS="$TESTENV/config-attestation-claims.gen.yaml"

setup_file() {
  local registry_user="testuser"
  local registry_pass="testpass"

  mkdir -p "$TESTENV/auth" "$TESTENV/auth-bad" "$TESTENV/registry"

  htpasswd -bnBC 10 "$registry_user" "$registry_pass" > "$TESTENV/zot-htpasswd"
  cat > "$TESTENV/zot-config.json" <<EOF
{
  "distSpecVersion": "1.1.0",
  "storage": {
    "rootDirectory": "$TESTENV/registry"
  },
  "http": {
    "address": "0.0.0.0",
    "port": "5000",
    "auth": {
      "htpasswd": {
        "path": "$TESTENV/zot-htpasswd"
      }
    }
  },
  "log": {
    "level": "warn"
  }
}
EOF

  zot serve "$TESTENV/zot-config.json" &

  for i in $(seq 1 30); do
    if curl -sf -u "$registry_user:$registry_pass" "http://localhost:5000/v2/" >/dev/null 2>&1; then
      break
    fi
    sleep 1
    if [[ "$i" -eq 30 ]]; then
      echo "ERROR: Zot did not become ready in 30s" >&2; return 1
    fi
  done

  pushd "$TESTENV" > /dev/null
  COSIGN_PASSWORD="" cosign generate-key-pair
  mv cosign.key cosign2.key
  mv cosign.pub cosign2.pub
  COSIGN_PASSWORD="" cosign generate-key-pair
  popd > /dev/null

  local auth_b64; auth_b64="$(printf '%s:%s' "$registry_user" "$registry_pass" | base64 -w0)"
  local auth_bad; auth_bad="$(printf '%s:%s' "$registry_user" "wrongpass"       | base64 -w0)"
  printf '{"auths":{"localhost:5000":{"auth":"%s"}}}\n' "$auth_b64" > "$TESTENV/auth/config.json"
  printf '{"auths":{"localhost:5000":{"auth":"%s"}}}\n' "$auth_bad" > "$TESTENV/auth-bad/config.json"

  cosign signing-config create 2>/dev/null \
    | jq '.rekorTlogUrls = []' \
    > "$TESTENV/signing-config.json"

  local f="$TESTENV"

  cat > "$f/config.gen.yaml" <<EOF
verification:
  mode: key
  key:
    path: $f/cosign.pub

registry:
  tls:
    insecure: true
  dockerConfigPath: $f/auth/config.json

referrers:
  manifestMediaType: application/vnd.test.k8s-manifests.v1+tar
  extractDir: manifests

airgap:
  skipTlog: true
EOF

  cat > "$f/config-additional-keys.gen.yaml" <<EOF
verification:
  mode: key
  key:
    path: $f/cosign.pub
  additional:
    - mode: key
      key:
        path: $f/cosign2.pub

registry:
  tls:
    insecure: true
  dockerConfigPath: $f/auth/config.json

referrers:
  manifestMediaType: application/vnd.test.k8s-manifests.v1+tar
  extractDir: manifests

airgap:
  skipTlog: true
EOF

  cat > "$f/config-bad-auth.gen.yaml" <<EOF
verification:
  mode: key
  key:
    path: $f/cosign.pub

registry:
  tls:
    insecure: true
  dockerConfigPath: $f/auth-bad/config.json

referrers:
  manifestMediaType: application/vnd.test.k8s-manifests.v1+tar
  extractDir: manifests

airgap:
  skipTlog: true
EOF

  cat > "$f/config-attestation.gen.yaml" <<EOF
verification:
  mode: key
  key:
    path: $f/cosign.pub
  required:
    - mode: attestation
      attestation:
        predicateType: https://example.com/blessing/v1
        signingMode: key
        key:
          path: $f/cosign.pub

registry:
  tls:
    insecure: true
  dockerConfigPath: $f/auth/config.json

referrers:
  manifestMediaType: application/vnd.test.k8s-manifests.v1+tar
  extractDir: manifests

airgap:
  skipTlog: true
EOF

  cat > "$f/config-attestation-claims.gen.yaml" <<EOF
verification:
  mode: key
  key:
    path: $f/cosign.pub
  required:
    - mode: attestation
      attestation:
        predicateType: https://example.com/blessing/v1
        signingMode: key
        key:
          path: $f/cosign.pub
        claims:
          approved: "true"
          reviewer: ci-bot@example.com

registry:
  tls:
    insecure: true
  dockerConfigPath: $f/auth/config.json

referrers:
  manifestMediaType: application/vnd.test.k8s-manifests.v1+tar
  extractDir: manifests

airgap:
  skipTlog: true
EOF

  cat > "$f/config-disallowed.gen.yaml" <<EOF
verification:
  mode: key
  key:
    path: $f/cosign.pub
  allowedRegistries:
    - registry.other.example.com

registry:
  tls:
    insecure: true
  dockerConfigPath: $f/auth/config.json

referrers:
  manifestMediaType: application/vnd.test.k8s-manifests.v1+tar
  extractDir: manifests

airgap:
  skipTlog: true
EOF
}

teardown_file() {
  pkill -f zot
  rm -rf "$TESTENV"
}

setup() {
  rm -rf "$WORKDIR"
  mkdir -p "$WORKDIR"
}

# 1: signed referrer happy path

@test "signed_referrer_happy_path" {
  push_image "inttest/app" "t1"
  sign "inttest/app" "t1"
  attach_bundle "inttest/app" "t1"

  run run_fetch "inttest/app" "t1" "$CFG"
  assert_success

  run run_generate "$CFG"
  assert_success
  assert_output --partial "kind: Deployment"
  assert_output --partial "kind: Service"
}

# 2: standalone bundle happy path

@test "standalone_bundle_happy_path" {
  push_bundle "inttest/bundle" "t2"
  sign "inttest/bundle" "t2"

  run run_fetch "inttest/bundle" "t2" "$CFG"
  assert_success

  run run_generate "$CFG"
  assert_success
  assert_output --partial "kind: Deployment"
}

# 3: fetch result metadata populated from OCI labels on app image

@test "fetch_result_metadata" {
  push_image "inttest/app" "meta"
  sign "inttest/app" "meta"
  attach_bundle "inttest/app" "meta"

  run run_fetch "inttest/app" "meta" "$CFG"
  assert_success

  local result="$WORKDIR/.argocd-cmp-fetch-result.json"
  run jq -r '.metadata.version' "$result"
  assert_output "test-meta"

  run jq -r '.metadata.authors' "$result"
  assert_output "Test Author <test@example.com>"

  run jq -r '.metadata.docsURL' "$result"
  assert_output "https://github.com/Patagia/argocd-verify-cmp"

  run jq -r '.metadata.sourceURL' "$result"
  assert_output "https://github.com/Patagia/argocd-verify-cmp/commit/abc1234567890abcdef1234567890abcdef123456"
}

# 4: unsigned image rejected

@test "unsigned_image_rejected" {
  push_image "inttest/app" "t3"

  run run_fetch "inttest/app" "t3" "$CFG"
  assert_failure
}

# 4: no referrer found

@test "no_referrer_found" {
  push_image "inttest/app" "t4"
  sign "inttest/app" "t4"

  run run_fetch "inttest/app" "t4" "$CFG"
  assert_failure
}

# 5: wrong referrer media type

@test "wrong_referrer_mediatype" {
  push_image "inttest/app" "t5"
  sign "inttest/app" "t5"
  attach_bundle "inttest/app" "t5" "application/vnd.other.bundle.v1+tar"

  run run_fetch "inttest/app" "t5" "$CFG"
  assert_failure
}

# 6: additional key fallback

@test "additional_key_fallback" {
  push_image "inttest/app" "t6"
  sign "inttest/app" "t6" "$TESTENV/cosign2.key"
  attach_bundle "inttest/app" "t6"

  run run_fetch "inttest/app" "t6" "$CFG_ADDL_KEYS"
  assert_success
}

# 7: non-OCI source passthrough

@test "non_oci_source_passthrough" {
  run env \
    ARGOCD_APP_SOURCE_REPO_URL="https://github.com/example/app" \
    ARGOCD_APP_SOURCE_TARGET_REVISION="main" \
    VERIFY_CMP_CONFIG="$CFG" \
    "$BINARY" fetch
  assert_success
}

# 8: disallowed registry

@test "disallowed_registry" {
  push_image "inttest/app" "t8"
  sign "inttest/app" "t8"

  run run_fetch "inttest/app" "t8" "$CFG_DISALLOWED"
  assert_failure
}

# 9: subpath scoping

@test "subpath_scoping" {
  local bundle_dir; bundle_dir="$(mktemp -d)"
  mkdir -p "$bundle_dir/overlays/production"
  echo "kind: ConfigMap" > "$bundle_dir/overlays/production/configmap.yaml"
  echo "kind: Secret"    > "$bundle_dir/root.yaml"

  local bundle_tar; bundle_tar="$(mktemp)"
  tar cf "$bundle_tar" -C "$bundle_dir" . 2>/dev/null

  oras push "$REGISTRY/inttest/subpath:t9" \
    --artifact-type "application/vnd.test.k8s-manifests.v1+tar" \
    --plain-http \
    --disable-path-validation \
    "$bundle_tar:application/vnd.oci.image.layer.v1.tar" 2>/dev/null
  sign "inttest/subpath" "t9"
  rm -rf "$bundle_dir" "$bundle_tar"

  run run_fetch "inttest/subpath" "t9" "$CFG"
  assert_success

  run run_generate "$CFG" "overlays/production"
  assert_success
  assert_output --partial "ConfigMap"
  refute_output --partial "Secret"
}

# 11: bundle with manifests under a subdirectory

@test "bundle_manifest_subdir" {
  local bundle_dir; bundle_dir="$(mktemp -d)"
  mkdir -p "$bundle_dir/app"
  echo "kind: Deployment" > "$bundle_dir/app/deploy.yaml"
  echo "kind: Service"    > "$bundle_dir/app/service.yaml"
  echo "kind: ConfigMap"  > "$bundle_dir/other.yaml"

  local bundle_tar; bundle_tar="$(mktemp)"
  tar cf "$bundle_tar" -C "$bundle_dir" . 2>/dev/null

  oras push "$REGISTRY/inttest/subdir:t11" \
    --artifact-type "application/vnd.test.k8s-manifests.v1+tar" \
    --plain-http \
    --disable-path-validation \
    "$bundle_tar:application/vnd.oci.image.layer.v1.tar" 2>/dev/null
  sign "inttest/subdir" "t11"
  rm -rf "$bundle_dir" "$bundle_tar"

  run run_fetch "inttest/subdir" "t11" "$CFG"
  assert_success

  run run_generate "$CFG" "app"
  assert_success
  assert_output --partial "Deployment"
  assert_output --partial "Service"
  refute_output --partial "ConfigMap"
}

# 12: attestation required — present and valid

@test "attestation_required_present" {
  push_image "inttest/app" "t12"
  sign "inttest/app" "t12"
  attest "inttest/app" "t12"
  attach_bundle "inttest/app" "t12"

  run run_fetch "inttest/app" "t12" "$CFG_ATTESTATION"
  assert_success
}

# 13: attestation required — missing → rejected

@test "attestation_required_missing" {
  push_image "inttest/app" "t13"
  sign "inttest/app" "t13"
  attach_bundle "inttest/app" "t13"

  run run_fetch "inttest/app" "t13" "$CFG_ATTESTATION"
  assert_failure
}

# 14: attestation required — wrong predicate type → rejected

@test "attestation_wrong_predicate_type" {
  push_image "inttest/app" "t14"
  sign "inttest/app" "t14"
  attest "inttest/app" "t14" "$TESTENV/cosign.key" "https://example.com/other/v1" '{"approved":true}'
  attach_bundle "inttest/app" "t14"

  run run_fetch "inttest/app" "t14" "$CFG_ATTESTATION"
  assert_failure
}

# 15: attestation with claims — all claims match

@test "attestation_claims_match" {
  push_image "inttest/app" "t15"
  sign "inttest/app" "t15"
  attest "inttest/app" "t15" "$TESTENV/cosign.key" "https://example.com/blessing/v1" \
    '{"approved":true,"reviewer":"ci-bot@example.com"}'
  attach_bundle "inttest/app" "t15"

  run run_fetch "inttest/app" "t15" "$CFG_ATTESTATION_CLAIMS"
  assert_success
}

# 16: attestation with claims — claim mismatch → rejected

@test "attestation_claims_mismatch" {
  push_image "inttest/app" "t16"
  sign "inttest/app" "t16"
  attest "inttest/app" "t16" "$TESTENV/cosign.key" "https://example.com/blessing/v1" \
    '{"approved":false,"reviewer":"ci-bot@example.com"}'
  attach_bundle "inttest/app" "t16"

  run run_fetch "inttest/app" "t16" "$CFG_ATTESTATION_CLAIMS"
  assert_failure
}

# 10: bad auth rejected

@test "bad_auth_rejected" {
  push_image "inttest/app" "t10"
  sign "inttest/app" "t10"
  attach_bundle "inttest/app" "t10"

  run run_fetch "inttest/app" "t10" "$CFG_BAD_AUTH"
  assert_failure
}
