#!/usr/bin/env bash
# setup.sh — start Zot registry and generate ephemeral test credentials.
# Run once before: bats test/integration/integration.bats
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGISTRY_USER="testuser"
REGISTRY_PASS="testpass"

echo "==> Generating htpasswd (bcrypt — required by Zot)..."
# htpasswd -bnBC 10: -b=batch, -n=stdout, -B=bcrypt, -C=cost
htpasswd -bnBC 10 "$REGISTRY_USER" "$REGISTRY_PASS" > "$SCRIPT_DIR/zot-htpasswd"

echo "==> Starting Zot registry..."
podman run -d --name verify-cmp-zot \
  -p 127.0.0.1:5000:5080 \
  -v "$SCRIPT_DIR/zot-config.json:/etc/zot/config.json:ro" \
  -v "$SCRIPT_DIR/zot-htpasswd:/etc/zot/htpasswd:ro" \
  ghcr.io/project-zot/zot-linux-amd64:latest serve /etc/zot/config.json

for i in $(seq 1 30); do
  if curl -sf -u "$REGISTRY_USER:$REGISTRY_PASS" "http://localhost:5000/v2/" >/dev/null 2>&1; then
    echo "    Zot ready at localhost:5000"
    break
  fi
  sleep 1
  if [[ "$i" -eq 30 ]]; then
    echo "ERROR: Zot did not become ready in 30s" >&2; exit 1
  fi
done

echo "==> Generating cosign key pairs..."
# Generate secondary key first (for additional_key_fallback test), then primary.
pushd "$SCRIPT_DIR/fixtures" > /dev/null
COSIGN_PASSWORD="" cosign generate-key-pair
mv cosign.key cosign2.key
mv cosign.pub cosign2.pub
COSIGN_PASSWORD="" cosign generate-key-pair
popd > /dev/null

echo "==> Writing docker credentials files..."
AUTH_B64="$(printf '%s:%s' "$REGISTRY_USER" "$REGISTRY_PASS" | base64 -w0)"
AUTH_BAD="$(printf '%s:%s' "$REGISTRY_USER" "wrongpass"       | base64 -w0)"
mkdir -p "$SCRIPT_DIR/fixtures/auth" "$SCRIPT_DIR/fixtures/auth-bad"
printf '{"auths":{"localhost:5000":{"auth":"%s"}}}\n' "$AUTH_B64" \
  > "$SCRIPT_DIR/fixtures/auth/config.json"
printf '{"auths":{"localhost:5000":{"auth":"%s"}}}\n' "$AUTH_BAD" \
  > "$SCRIPT_DIR/fixtures/auth-bad/config.json"

echo "==> Generating air-gap signing config (no Rekor TLog)..."
SIGNING_CFG="$SCRIPT_DIR/fixtures/signing-config.json"
cosign signing-config create 2>/dev/null \
  | jq '.rekorTlogUrls = []' \
  > "$SIGNING_CFG"

echo "==> Writing fixture configs with host paths..."
F="$SCRIPT_DIR/fixtures"

cat > "$F/config.gen.yaml" <<EOF
verification:
  mode: key
  key:
    path: $F/cosign.pub

registry:
  tls:
    insecure: true
  dockerConfigPath: $F/auth/config.json

referrers:
  manifestMediaType: application/vnd.test.k8s-manifests.v1+tar
  extractDir: /tmp/manifests

airgap:
  skipTlog: true
EOF

cat > "$F/config-additional-keys.gen.yaml" <<EOF
verification:
  mode: key
  key:
    path: $F/cosign.pub
  additionalKeys:
    - $F/cosign2.pub

registry:
  tls:
    insecure: true
  dockerConfigPath: $F/auth/config.json

referrers:
  manifestMediaType: application/vnd.test.k8s-manifests.v1+tar
  extractDir: /tmp/manifests

airgap:
  skipTlog: true
EOF

cat > "$F/config-bad-auth.gen.yaml" <<EOF
verification:
  mode: key
  key:
    path: $F/cosign.pub

registry:
  tls:
    insecure: true
  dockerConfigPath: $F/auth-bad/config.json

referrers:
  manifestMediaType: application/vnd.test.k8s-manifests.v1+tar
  extractDir: /tmp/manifests

airgap:
  skipTlog: true
EOF

cat > "$F/config-disallowed.gen.yaml" <<EOF
verification:
  mode: key
  key:
    path: $F/cosign.pub
  allowedRegistries:
    - registry.other.example.com

registry:
  tls:
    insecure: true
  dockerConfigPath: $F/auth/config.json

referrers:
  manifestMediaType: application/vnd.test.k8s-manifests.v1+tar
  extractDir: /tmp/manifests

airgap:
  skipTlog: true
EOF

echo "==> Setup complete."
echo "    Registry:    localhost:5000"
echo "    Credentials: ${REGISTRY_USER}:${REGISTRY_PASS}"
