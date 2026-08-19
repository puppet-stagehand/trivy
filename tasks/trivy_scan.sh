#!/bin/sh
# trivy::trivy_scan — run Trivy on a node, normalize to compliance.v1 with the
# bundled adapter, and POST to the console. Self-contained: the adapter ships
# with the task via metadata "files" and is resolved through $PT__installdir.
set -u

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# fail_json REASON
#
# Sibling to die() for BUSINESS-LOGIC failures only (a download/checksum/
# install/scan/adapter/POST step that ran but failed) -- as opposed to
# die()'s SETUP failures (missing console_url, missing adapter, missing jq,
# a malformed scan_path). Emits the established
# {"status": "error", "error": "...", "scanner": "trivy"} embedded-status
# contract (AUDIT-04, matching install_ansible.sh/discover.sh/patch.sh) on
# stdout and exits 0, so the console/orchestrator can always parse the
# outcome instead of an opaque stderr blob and a bare non-zero exit.
fail_json() { printf '{"status": "error", "error": "%s", "scanner": "trivy"}\n' "$*"; exit 0; }

# TRIVY_SCAN_PUPPET_BIN exists solely so tests can point the certname lookup
# at a stub puppet binary on a curated PATH instead of the real
# /opt/puppetlabs/bin/puppet (which may be genuinely installed on the
# dev/test host, mirroring STAGEHAND_RECERT_PUPPET_BIN/STAGEHAND_DISCOVER_PUPPET_BIN's
# established convention). It is NEVER a Bolt param.
PUPPET_BIN="${TRIVY_SCAN_PUPPET_BIN:-/opt/puppetlabs/bin/puppet}"

CONSOLE="${PT_console_url:-}"
TOKEN="${PT_ingest_token:-}"
SCAN_PATH="${PT_scan_path:-/}"
INSTALL="${PT_install:-false}"

# scan_path becomes the final, unguarded positional argv element in the
# `trivy rootfs ... "$SCAN_PATH"` invocation below. Shell quoting prevents
# word-splitting but does NOT prevent a value like "--severity=CRITICAL"
# from being parsed as a FLAG by trivy's own cobra-based CLI argument
# parser -- empirically verified against a live trivy v0.70.0 binary during
# this phase's research session (see 02-RESEARCH.md Pitfall 1). Reject a
# leading-dash value before it ever reaches trivy's argv. trivy_scan.json's
# Pattern-typed scan_path rejects this too, but this task must not trust
# that Bolt is always the caller (same two-layer validation idiom as
# patch.sh's patch_ids regex). This stays a hard die()/exit 1 input-
# validation gate (D-05), not embedded-JSON.
case "$SCAN_PATH" in
  -*) die "scan_path must not start with '-' (would be misparsed as a trivy flag)" ;;
esac

[ -n "$CONSOLE" ] || die "console_url is required"

INSTALLDIR="${PT__installdir:-}"
ADAPTER="${INSTALLDIR}/trivy/files/trivy-report.sh"
[ -f "$ADAPTER" ] || die "trivy-report adapter not found at $ADAPTER"
command -v jq >/dev/null 2>&1 || die "jq is required on the target for the trivy adapter"

# Pinned release + checksum verification (FND-09 / CVE-2026-33634). This
# replaces the previous unpinned install by piping the aquasecurity/trivy
# repo's main-branch installer shell script into `sh`, which trusted whatever
# the `main` branch (or a `latest` tag) currently contained -- exactly the
# vector CVE-2026-33634 turned into a live supply-chain compromise via the
# malicious v0.69.4/v0.69.5/v0.69.6 releases (GHSA-69fq-xp46-6x23). Re-verify
# this pin (version + checksum) against
# https://github.com/aquasecurity/trivy/releases before bumping it -- never
# pin 0.69.4/0.69.5/0.69.6.
TRIVY_VERSION="0.72.0"
TRIVY_ASSET="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
TRIVY_BASE="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}"

if ! command -v trivy >/dev/null 2>&1; then
  if [ "$INSTALL" = "true" ]; then
    printf '>>> installing trivy %s (checksum-verified)\n' "$TRIVY_VERSION" >&2
    TMPDIR=$(mktemp -d) || die "mktemp -d failed"

    curl -sfL "$TRIVY_BASE/$TRIVY_ASSET" -o "$TMPDIR/$TRIVY_ASSET" \
      || fail_json "trivy download failed"
    curl -sfL "$TRIVY_BASE/trivy_${TRIVY_VERSION}_checksums.txt" -o "$TMPDIR/checksums.txt" \
      || fail_json "trivy checksums.txt download failed"

    EXPECTED=$(grep " $TRIVY_ASSET\$" "$TMPDIR/checksums.txt" | awk '{print $1}')
    [ -n "$EXPECTED" ] || fail_json "no checksum entry found for $TRIVY_ASSET in checksums.txt"
    ACTUAL=$(sha256sum "$TMPDIR/$TRIVY_ASSET" | awk '{print $1}')
    [ "$EXPECTED" = "$ACTUAL" ] || fail_json "trivy checksum mismatch: expected $EXPECTED got $ACTUAL"

    tar -xzf "$TMPDIR/$TRIVY_ASSET" -C "$TMPDIR" trivy || fail_json "trivy tarball extraction failed"
    install -m 0755 "$TMPDIR/trivy" /usr/local/bin/trivy || fail_json "trivy install failed"
    rm -rf "$TMPDIR"
  else
    fail_json "trivy not installed (pass install=true to auto-install)"
  fi
fi

CERT=$("$PUPPET_BIN" config print certname 2>/dev/null || hostname -f 2>/dev/null || hostname)
REPORT=$(mktemp) || die "mktemp failed"
trap 'rm -f "$REPORT"' EXIT

printf '>>> trivy rootfs --scanners vuln %s\n' "$SCAN_PATH" >&2
trivy rootfs --scanners vuln --format json -o "$REPORT" "$SCAN_PATH" 2>/dev/null || true
[ -s "$REPORT" ] || fail_json "trivy produced no report"

BATCH=$(bash "$ADAPTER" --report "$REPORT" --certname "$CERT") || fail_json "adapter normalization failed"

if [ -n "$TOKEN" ]; then
  printf '%s' "$BATCH" | curl -sf -X POST "$CONSOLE/api/v1/compliance/results" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' --data-binary @- >/dev/null \
    || fail_json "POST to console failed"
else
  printf '%s' "$BATCH" | curl -sf -X POST "$CONSOLE/api/v1/compliance/results" \
    -H 'Content-Type: application/json' --data-binary @- >/dev/null \
    || fail_json "POST to console failed"
fi

printf '{"status": "scanned", "scanner": "trivy", "certname": "%s"}\n' "$CERT"
