#!/usr/bin/env bash
# teardown.sh — stop Zot and remove all generated files.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Stopping Zot..."
podman stop verify-cmp-zot 2>/dev/null || true
podman rm   verify-cmp-zot 2>/dev/null || true

echo "==> Removing generated files..."
rm -f  "$SCRIPT_DIR/zot-htpasswd" \
       "$SCRIPT_DIR/fixtures/signing-config.json" \
       "$SCRIPT_DIR/fixtures/cosign.key" \
       "$SCRIPT_DIR/fixtures/cosign.pub" \
       "$SCRIPT_DIR/fixtures/cosign2.key" \
       "$SCRIPT_DIR/fixtures/cosign2.pub" \
       "$SCRIPT_DIR/fixtures"/*.gen.yaml
rm -rf "$SCRIPT_DIR/fixtures/auth" \
       "$SCRIPT_DIR/fixtures/auth-bad"

echo "==> Teardown complete."
