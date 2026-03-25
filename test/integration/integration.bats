#!/usr/bin/env bats
# integration.bats — integration tests for verify-cmp.
# Requires setup.sh to have been run first.

bats_load_library bats-support
bats_load_library bats-assert
load helpers

CFG="$FIXTURES/config.gen.yaml"
CFG_BAD_AUTH="$FIXTURES/config-bad-auth.gen.yaml"
CFG_ADDL_KEYS="$FIXTURES/config-additional-keys.gen.yaml"
CFG_DISALLOWED="$FIXTURES/config-disallowed.gen.yaml"

setup() {
  rm -rf /tmp/manifests
  mkdir -p /tmp/manifests
}

# ── 1: signed referrer happy path ────────────────────────────────────────────

@test "signed_referrer_happy_path" {
  push_image "inttest/app" "t1"
  sign "inttest/app" "t1"
  attach_bundle "inttest/app" "t1"

  run run_init "inttest/app" "t1" "$CFG"
  assert_success

  run run_generate "$CFG"
  assert_success
  assert_output --partial "kind: Deployment"
  assert_output --partial "kind: Service"
}

# ── 2: standalone bundle happy path ──────────────────────────────────────────

@test "standalone_bundle_happy_path" {
  push_bundle "inttest/bundle" "t2"
  sign "inttest/bundle" "t2"

  run run_init "inttest/bundle" "t2" "$CFG"
  assert_success

  run run_generate "$CFG"
  assert_success
  assert_output --partial "kind: Deployment"
}

# ── 3: unsigned image rejected ────────────────────────────────────────────────

@test "unsigned_image_rejected" {
  push_image "inttest/app" "t3"

  run run_init "inttest/app" "t3" "$CFG"
  assert_failure
}

# ── 4: no referrer found ──────────────────────────────────────────────────────

@test "no_referrer_found" {
  push_image "inttest/app" "t4"
  sign "inttest/app" "t4"

  run run_init "inttest/app" "t4" "$CFG"
  assert_failure
}

# ── 5: wrong referrer media type ──────────────────────────────────────────────

@test "wrong_referrer_mediatype" {
  push_image "inttest/app" "t5"
  sign "inttest/app" "t5"
  attach_bundle "inttest/app" "t5" "application/vnd.other.bundle.v1+tar"

  run run_init "inttest/app" "t5" "$CFG"
  assert_failure
}

# ── 6: additional key fallback ────────────────────────────────────────────────

@test "additional_key_fallback" {
  push_image "inttest/app" "t6"
  sign "inttest/app" "t6" "$FIXTURES/cosign2.key"
  attach_bundle "inttest/app" "t6"

  run run_init "inttest/app" "t6" "$CFG_ADDL_KEYS"
  assert_success
}

# ── 7: non-OCI source passthrough ─────────────────────────────────────────────

@test "non_oci_source_passthrough" {
  run env \
    ARGOCD_APP_SOURCE_REPO_URL="https://github.com/example/app" \
    ARGOCD_APP_SOURCE_TARGET_REVISION="main" \
    VERIFY_CMP_CONFIG="$CFG" \
    "$BINARY" init
  assert_success
}

# ── 8: disallowed registry ────────────────────────────────────────────────────

@test "disallowed_registry" {
  push_image "inttest/app" "t8"
  sign "inttest/app" "t8"

  run run_init "inttest/app" "t8" "$CFG_DISALLOWED"
  assert_failure
}

# ── 9: subpath scoping ────────────────────────────────────────────────────────

@test "subpath_scoping" {
  local bundle_dir; bundle_dir="$(mktemp -d)"
  mkdir -p "$bundle_dir/overlays/production"
  echo "kind: Kustomization" > "$bundle_dir/overlays/production/kustomization.yaml"
  echo "kind: Root"          > "$bundle_dir/root.yaml"

  local bundle_tar; bundle_tar="$(mktemp)"
  tar cf "$bundle_tar" -C "$bundle_dir" . 2>/dev/null

  oras push "$REGISTRY/inttest/subpath:t9" \
    --artifact-type "application/vnd.test.k8s-manifests.v1+tar" \
    --plain-http \
    --disable-path-validation \
    "$bundle_tar:application/vnd.oci.image.layer.v1.tar" 2>/dev/null
  sign "inttest/subpath" "t9"
  rm -rf "$bundle_dir" "$bundle_tar"

  run run_init "inttest/subpath" "t9" "$CFG"
  assert_success

  run run_generate "$CFG" "overlays/production"
  assert_success
  assert_output --partial "Kustomization"
  refute_output --partial "Root"
}

# ── 10: bad auth rejected ─────────────────────────────────────────────────────

@test "bad_auth_rejected" {
  push_image "inttest/app" "t10"
  sign "inttest/app" "t10"
  attach_bundle "inttest/app" "t10"

  run run_init "inttest/app" "t10" "$CFG_BAD_AUTH"
  assert_failure
}
