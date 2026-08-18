#!/bin/sh
# trivy::trivy_scan — run Trivy on a node, normalize to compliance.v1 with the
# bundled adapter, and POST to the console. Self-contained: the adapter ships
# with the task via metadata "files" and is resolved through $PT__installdir.
set -u

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

CONSOLE="${PT_console_url:-}"
TOKEN="${PT_ingest_token:-}"
SCAN_PATH="${PT_scan_path:-/}"
INSTALL="${PT_install:-false}"

[ -n "$CONSOLE" ] || die "console_url is required"

INSTALLDIR="${PT__installdir:-}"
ADAPTER="${INSTALLDIR}/trivy/files/trivy-report.sh"
[ -f "$ADAPTER" ] || die "trivy-report adapter not found at $ADAPTER"
command -v jq >/dev/null 2>&1 || die "jq is required on the target for the trivy adapter"

if ! command -v trivy >/dev/null 2>&1; then
  if [ "$INSTALL" = "true" ]; then
    printf '>>> installing trivy\n'
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin >/dev/null 2>&1 || die "trivy install failed"
  else
    die "trivy not installed (pass install=true to auto-install)"
  fi
fi

CERT=$(/opt/puppetlabs/bin/puppet config print certname 2>/dev/null || hostname -f 2>/dev/null || hostname)
REPORT=$(mktemp) || die "mktemp failed"
trap 'rm -f "$REPORT"' EXIT

printf '>>> trivy rootfs --scanners vuln %s\n' "$SCAN_PATH"
trivy rootfs --scanners vuln --format json -o "$REPORT" "$SCAN_PATH" 2>/dev/null || true
[ -s "$REPORT" ] || die "trivy produced no report"

BATCH=$(bash "$ADAPTER" --report "$REPORT" --certname "$CERT") || die "adapter normalization failed"

if [ -n "$TOKEN" ]; then
  printf '%s' "$BATCH" | curl -sf -X POST "$CONSOLE/api/v1/compliance/results" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' --data-binary @- >/dev/null \
    || die "POST to console failed"
else
  printf '%s' "$BATCH" | curl -sf -X POST "$CONSOLE/api/v1/compliance/results" \
    -H 'Content-Type: application/json' --data-binary @- >/dev/null \
    || die "POST to console failed"
fi

printf '{"status": "scanned", "scanner": "trivy", "certname": "%s"}\n' "$CERT"
