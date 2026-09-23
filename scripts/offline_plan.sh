#!/usr/bin/env bash
# Produce `terraform show -json` output for a root module without Azure
# credentials, using scripts/mock_arm.py for metadata and token endpoints.
#
# Usage: scripts/offline_plan.sh <terraform-root-dir> <output.json> [vars.tfvars]
#
# The module is copied to a temporary directory and its backend is overridden
# with a local one, so the working tree is never modified.
set -euo pipefail

log() { printf '%s offline-plan: %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

[[ $# -ge 2 && $# -le 3 ]] || die "usage: $0 <terraform-root-dir> <output.json> [vars.tfvars]"

[[ -d "$1" ]] || die "module directory $1 not found"
[[ -d "$(dirname "$2")" ]] || die "output directory $(dirname "$2") not found"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(cd "$1" && pwd)"
OUTPUT="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
readonly SCRIPT_DIR MODULE_DIR OUTPUT
VAR_FILE=""
if [[ $# -eq 3 ]]; then
  [[ -f "$3" ]] || die "var file $3 not found"
  VAR_FILE="$(cd "$(dirname "$3")" && pwd)/$(basename "$3")"
fi
readonly PORT="${MOCK_ARM_PORT:-8443}"
[[ "$PORT" =~ ^[0-9]+$ ]] || die "MOCK_ARM_PORT must be numeric"

for bin in terraform openssl python3 curl; do
  command -v "$bin" >/dev/null 2>&1 || die "$bin is required"
done
ls "$MODULE_DIR"/*.tf >/dev/null 2>&1 || die "$MODULE_DIR contains no .tf files"

WORK="$(mktemp -d)"
SERVER_PID=""
cleanup() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

log "copying $MODULE_DIR"
mkdir -p "$WORK/module"
tar --exclude=.terraform --exclude='*.tfstate*' -C "$MODULE_DIR" -cf - . | tar -C "$WORK/module" -xf -
cat > "$WORK/module/zz_offline_backend_override.tf" <<'EOF'
terraform {
  backend "local" {}
}
EOF

log "generating throwaway TLS certificate for localhost"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1 \
  || die "certificate generation failed"

SYSTEM_BUNDLE="${SSL_CERT_FILE:-/etc/ssl/certs/ca-certificates.crt}"
[[ -f "$SYSTEM_BUNDLE" ]] || die "CA bundle $SYSTEM_BUNDLE not found; set SSL_CERT_FILE"
cat "$SYSTEM_BUNDLE" "$WORK/cert.pem" > "$WORK/ca-bundle.pem"

log "starting mock ARM on port $PORT"
python3 "$SCRIPT_DIR/mock_arm.py" --port "$PORT" --cert "$WORK/cert.pem" --key "$WORK/key.pem" \
  2> "$WORK/mock_arm.log" &
SERVER_PID=$!

for _ in $(seq 1 50); do
  if curl -fsS --cacert "$WORK/cert.pem" "https://localhost:${PORT}/metadata/endpoints?api-version=2022-09-01" >/dev/null 2>&1; then
    break
  fi
  kill -0 "$SERVER_PID" 2>/dev/null || { cat "$WORK/mock_arm.log" >&2; die "mock ARM exited"; }
  sleep 0.2
done
curl -fsS --cacert "$WORK/cert.pem" "https://localhost:${PORT}/metadata/endpoints?api-version=2022-09-01" >/dev/null \
  || die "mock ARM did not become ready"

cd "$WORK/module"
log "terraform init"
terraform init -input=false -no-color -lockfile=readonly >/dev/null

plan_args=(-input=false -no-color -refresh=false -lock=false -out="$WORK/tfplan")
[[ -n "$VAR_FILE" ]] && plan_args+=(-var-file="$VAR_FILE")

log "terraform plan (offline)"
if ! env \
    SSL_CERT_FILE="$WORK/ca-bundle.pem" \
    ARM_METADATA_HOSTNAME="localhost:${PORT}" \
    ARM_ENVIRONMENT="AzureCloud" \
    ARM_USE_OIDC="false" \
    ARM_USE_CLI="false" \
    ARM_USE_MSI="false" \
    ARM_CLIENT_ID="33333333-3333-3333-3333-333333333333" \
    ARM_CLIENT_SECRET="offline-plan-not-a-secret" \
    ARM_TENANT_ID="11111111-1111-1111-1111-111111111111" \
    ARM_SUBSCRIPTION_ID="44444444-4444-4444-4444-444444444444" \
    terraform plan "${plan_args[@]}" > "$WORK/plan.log" 2>&1; then
  cat "$WORK/plan.log" >&2
  log "mock ARM log:"
  cat "$WORK/mock_arm.log" >&2
  die "terraform plan failed"
fi

if grep -q "unexpected request" "$WORK/mock_arm.log"; then
  cat "$WORK/mock_arm.log" >&2
  die "provider made API calls the mock does not serve; the offline plan is not trustworthy"
fi

terraform show -json "$WORK/tfplan" > "$OUTPUT"
log "wrote $OUTPUT ($(grep -c . "$WORK/plan.log") plan log lines, summary: $(grep -E '^Plan:' "$WORK/plan.log" || echo 'no changes'))"
