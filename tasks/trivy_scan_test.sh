#!/bin/sh
# trivy::trivy_scan leading-dash scan_path guard + JSON-on-fail contract test
# harness (02-04-PLAN.md Task 1). Follows r10k_deploy_test.sh's env -i
# isolation pattern; trivy_scan.sh had zero test coverage before this phase.
#
# Safety: trivy (real binary at /opt/homebrew/bin on this host), curl (real
# binary at /usr/bin), and the certname puppet lookup (a real, executable
# binary at the hardcoded /opt/puppetlabs/bin/puppet path on this host,
# confirmed via `ls -la` before this phase's TRIVY_SCAN_PUPPET_BIN override
# was added as its own safety-prerequisite commit) are ALL fully stubbed.
# PATH is curated to a shim dir plus minimal system dirs that do NOT
# include /opt/homebrew/bin or /opt/puppetlabs/bin, and every invocation
# runs under env -i so no ambient env var can leak a path to a real binary.
# No case here ever reaches a real network call, a real trivy invocation,
# or the real puppet CLI. The trivy tarball install (checksum verify +
# `install -m 0755 ... /usr/local/bin/trivy`) is never exercised past the
# checksum-mismatch/download-failure steps by any case below -- no case
# writes to /usr/local/bin.
#
# Cases (see 02-04-PLAN.md Task 1 <behavior>):
#   (1) PT_scan_path = "-x" -> die()/exit 1, trivy stub NEVER invoked.
#   (2) PT_scan_path = "-"  -> die()/exit 1, trivy stub NEVER invoked.
#   (3) simulated curl download failure (install path) -> embedded JSON
#       error "trivy download failed", exit 0.
#   (4) simulated checksum mismatch -> embedded JSON error mentioning
#       "checksum mismatch", exit 0.
#   (5) simulated scan producing an empty report -> embedded JSON error
#       "trivy produced no report", exit 0.
#   (6) simulated POST failure -> embedded JSON error "POST to console
#       failed", exit 0.
#   (7) success path (unset scan_path -> default "/", stub trivy + stub
#       curl POST succeed) -> {"status":"scanned","scanner":"trivy",...}
#       (regression, unchanged shape; also proves the empty-scan_path
#       default is NOT flagged by the new guard).
#   (8) trivy_scan.json: ingest_token.sensitive == "true", scan_path.type
#       contains "Pattern", input_method == "both".

set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd) || exit 1
TARGET_SH="$SCRIPT_DIR/trivy_scan.sh"
TARGET_JSON="$SCRIPT_DIR/trivy_scan.json"
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd) || exit 1

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
info() { printf '>>> %s\n' "$*"; }

[ -f "$TARGET_SH" ] || fail "trivy_scan.sh not found at $TARGET_SH"
[ -f "$TARGET_JSON" ] || fail "trivy_scan.json not found at $TARGET_JSON"
command -v jq >/dev/null 2>&1 || fail "jq is required to run this test harness"
[ -f "$REPO_ROOT/trivy/files/trivy-report.sh" ] || fail "trivy-report.sh adapter not found under REPO_ROOT ($REPO_ROOT) — PT__installdir resolution is wrong"

WORK=$(mktemp -d) || fail "mktemp -d failed"
trap 'rm -rf "$WORK"' EXIT

SHIMDIR="$WORK/shims"
mkdir -p "$SHIMDIR" || fail "could not create shim dir"

ARGV_LOG="$WORK/argv.log"
export ARGV_LOG

# Fixture trivy-JSON report the stub trivy binary "produces" — a minimal
# valid report the REAL bundled trivy-report.sh adapter can normalize
# without any adapter-side stubbing (jq is already installed locally, per
# the plan's key_links).
FIXTURE_REPORT="$WORK/fixture-trivy-report.json"
cat > "$FIXTURE_REPORT" <<'FIXTURE'
{
  "SchemaVersion": 2,
  "Results": [
    {
      "Target": "test-target",
      "Vulnerabilities": []
    }
  ]
}
FIXTURE

# puppet-stub — logs its own argv, prints a fixed certname for "config
# print certname". Never the real puppet binary; wired in via
# TRIVY_SCAN_PUPPET_BIN, not PATH (the real cert lookup is a hardcoded
# absolute path, immune to PATH shimming).
cat > "$SHIMDIR/puppet-stub" <<SHIM
#!/bin/sh
printf 'puppet %s\n' "\$*" >> "$ARGV_LOG"
case "\$*" in
  *"config print certname"*) printf 'test-node.example.com\n'; exit 0 ;;
  *) exit 1 ;;
esac
SHIM
chmod +x "$SHIMDIR/puppet-stub"

# make_trivy_stub — writes a PATH shim named "trivy" that logs its own argv
# and, only if SHIM_TRIVY_WRITE_REPORT is exported "1", writes
# FIXTURE_REPORT to the path following "-o" in its argv. Never the real
# trivy binary (real trivy lives at /opt/homebrew/bin, deliberately
# excluded from TEST_PATH below — this stub is also absent entirely for
# cases that test the "trivy not installed" install path).
make_trivy_stub() {
  cat > "$SHIMDIR/trivy" <<SHIM
#!/bin/sh
printf 'trivy %s\n' "\$*" >> "$ARGV_LOG"
out=""
prev=""
for a in "\$@"; do
  if [ "\$prev" = "-o" ]; then out="\$a"; fi
  prev="\$a"
done
if [ "\${SHIM_TRIVY_WRITE_REPORT:-0}" = "1" ] && [ -n "\$out" ]; then
  cat "$FIXTURE_REPORT" > "\$out"
fi
exit 0
SHIM
  chmod +x "$SHIMDIR/trivy"
}

# curl stub — logs its own argv. Handles two call shapes:
#   - a POST to the console ingest endpoint (argv contains "-X" "POST"),
#     controllable via SHIM_CURL_POST_SUCCEED (default: succeed).
#   - a download (-o <path> <url>), controllable via
#     SHIM_CURL_DOWNLOAD_SUCCEED (default: succeed). On a "succeeding"
#     download, writes deterministic fixture content to the -o path: a
#     checksums.txt line with an all-zero checksum for the pinned asset
#     name (trivy_scan.sh pins TRIVY_VERSION=0.72.0, so the asset name is
#     "trivy_0.72.0_Linux-64bit.tar.gz" — this stub hardcodes that so the
#     checksum-mismatch case is exercised deterministically), otherwise
#     dummy tarball bytes whose real sha256 will never equal the all-zero
#     stub checksum. Never makes a real network call.
cat > "$SHIMDIR/curl" <<SHIM
#!/bin/sh
printf 'curl %s\n' "\$*" >> "$ARGV_LOG"

is_post=0
prev=""
for a in "\$@"; do
  if [ "\$prev" = "-X" ] && [ "\$a" = "POST" ]; then is_post=1; fi
  prev="\$a"
done

if [ "\$is_post" = "1" ]; then
  [ "\${SHIM_CURL_POST_SUCCEED:-1}" = "1" ] && exit 0
  exit 1
fi

[ "\${SHIM_CURL_DOWNLOAD_SUCCEED:-1}" = "1" ] || exit 1

out=""
prev=""
url=""
for a in "\$@"; do
  if [ "\$prev" = "-o" ]; then out="\$a"; fi
  prev="\$a"
  case "\$a" in
    http*) url="\$a" ;;
  esac
done
case "\$url" in
  *checksums.txt)
    printf '0000000000000000000000000000000000000000000000000000000000000000  trivy_0.72.0_Linux-64bit.tar.gz\n' > "\$out"
    ;;
  *)
    printf 'dummytrivybinarydata' > "\$out"
    ;;
esac
exit 0
SHIM
chmod +x "$SHIMDIR/curl"

TEST_PATH="$SHIMDIR:/usr/bin:/bin:/usr/sbin:/sbin"

# run_trivy_scan SCAN_PATH INSTALL — invokes trivy_scan.sh in an isolated
# environment (env -i) so no ambient env var can accidentally reach a real
# binary. Only PATH, HOME, PT__installdir (repo root, so the real bundled
# adapter resolves), and the explicit PT_*/TRIVY_SCAN_PUPPET_BIN/SHIM_* vars
# trivy_scan.sh or this harness reads are passed through.
run_trivy_scan() {
  scan_path="${1-}"
  install="${2:-false}"
  env -i \
    PATH="$TEST_PATH" \
    HOME="$HOME" \
    PT_console_url="https://console.example.com" \
    PT_ingest_token="test-token" \
    PT_scan_path="$scan_path" \
    PT_install="$install" \
    PT__installdir="$REPO_ROOT" \
    TRIVY_SCAN_PUPPET_BIN="$SHIMDIR/puppet-stub" \
    SHIM_TRIVY_WRITE_REPORT="${SHIM_TRIVY_WRITE_REPORT:-0}" \
    SHIM_CURL_DOWNLOAD_SUCCEED="${SHIM_CURL_DOWNLOAD_SUCCEED:-1}" \
    SHIM_CURL_POST_SUCCEED="${SHIM_CURL_POST_SUCCEED:-1}" \
    sh "$TARGET_SH"
}

reset() {
  : > "$ARGV_LOG"
  rm -f "$SHIMDIR/trivy"
  SHIM_TRIVY_WRITE_REPORT=0
  SHIM_CURL_DOWNLOAD_SUCCEED=1
  SHIM_CURL_POST_SUCCEED=1
}

# --- Case 1: PT_scan_path = "-x" -> die()/exit 1, trivy stub NEVER invoked. ---
reset
OUT=$(run_trivy_scan '-x' false 2>"$WORK/stderr.1")
RC=$?
STDERR1=$(cat "$WORK/stderr.1")
[ "$RC" -eq 1 ] || fail "case 1 (scan_path=-x): expected exit 1, got $RC. stdout: $OUT"
case "$STDERR1" in
  *"scan_path must not start with '-'"*) : ;;
  *) fail "case 1 (scan_path=-x): expected stderr to mention the leading-dash guard, got: $STDERR1" ;;
esac
[ -s "$ARGV_LOG" ] && fail "case 1 (scan_path=-x): trivy/curl/puppet stub was invoked but should not have been. argv log:
$(cat "$ARGV_LOG")"
info "case 1 (scan_path=-x): OK (die()/exit 1, no stub invoked)"

# --- Case 2: PT_scan_path = "-" (boundary) -> die()/exit 1, trivy stub NEVER invoked. ---
reset
OUT=$(run_trivy_scan '-' false 2>"$WORK/stderr.2")
RC=$?
STDERR2=$(cat "$WORK/stderr.2")
[ "$RC" -eq 1 ] || fail "case 2 (scan_path=-): expected exit 1, got $RC. stdout: $OUT"
case "$STDERR2" in
  *"scan_path must not start with '-'"*) : ;;
  *) fail "case 2 (scan_path=-): expected stderr to mention the leading-dash guard, got: $STDERR2" ;;
esac
[ -s "$ARGV_LOG" ] && fail "case 2 (scan_path=-): trivy/curl/puppet stub was invoked but should not have been. argv log:
$(cat "$ARGV_LOG")"
info "case 2 (scan_path=-): OK (die()/exit 1, no stub invoked)"

# --- Case 3: simulated curl download failure (install path) -> embedded JSON error, exit 0. ---
reset
SHIM_CURL_DOWNLOAD_SUCCEED=0
OUT=$(run_trivy_scan '/' true)
RC=$?
[ "$RC" -eq 0 ] || fail "case 3 (download failure): expected exit 0 (status embedded), got $RC. stdout: $OUT"
STATUS3=$(printf '%s' "$OUT" | jq -r '.status' 2>/dev/null)
ERROR3=$(printf '%s' "$OUT" | jq -r '.error' 2>/dev/null)
SCANNER3=$(printf '%s' "$OUT" | jq -r '.scanner' 2>/dev/null)
[ "$STATUS3" = "error" ] || fail "case 3 (download failure): expected status 'error', got: $STATUS3. stdout: $OUT"
[ "$SCANNER3" = "trivy" ] || fail "case 3 (download failure): expected scanner 'trivy', got: $SCANNER3. stdout: $OUT"
case "$ERROR3" in
  *"trivy download failed"*) : ;;
  *) fail "case 3 (download failure): expected error to mention 'trivy download failed', got: $ERROR3" ;;
esac
info "case 3 (download failure): OK (embedded JSON error, exit 0)"

# --- Case 4: simulated checksum mismatch -> embedded JSON error, exit 0. ---
reset
SHIM_CURL_DOWNLOAD_SUCCEED=1
OUT=$(run_trivy_scan '/' true)
RC=$?
[ "$RC" -eq 0 ] || fail "case 4 (checksum mismatch): expected exit 0 (status embedded), got $RC. stdout: $OUT"
STATUS4=$(printf '%s' "$OUT" | jq -r '.status' 2>/dev/null)
ERROR4=$(printf '%s' "$OUT" | jq -r '.error' 2>/dev/null)
[ "$STATUS4" = "error" ] || fail "case 4 (checksum mismatch): expected status 'error', got: $STATUS4. stdout: $OUT"
case "$ERROR4" in
  *"checksum mismatch"*) : ;;
  *) fail "case 4 (checksum mismatch): expected error to mention 'checksum mismatch', got: $ERROR4" ;;
esac
info "case 4 (checksum mismatch): OK (embedded JSON error, exit 0)"

# --- Case 5: simulated scan producing an empty report -> embedded JSON error, exit 0. ---
reset
make_trivy_stub
SHIM_TRIVY_WRITE_REPORT=0
OUT=$(run_trivy_scan '/' false)
RC=$?
[ "$RC" -eq 0 ] || fail "case 5 (empty report): expected exit 0 (status embedded), got $RC. stdout: $OUT"
STATUS5=$(printf '%s' "$OUT" | jq -r '.status' 2>/dev/null)
ERROR5=$(printf '%s' "$OUT" | jq -r '.error' 2>/dev/null)
[ "$STATUS5" = "error" ] || fail "case 5 (empty report): expected status 'error', got: $STATUS5. stdout: $OUT"
case "$ERROR5" in
  *"trivy produced no report"*) : ;;
  *) fail "case 5 (empty report): expected error to mention 'trivy produced no report', got: $ERROR5" ;;
esac
grep -q '^trivy ' "$ARGV_LOG" || fail "case 5 (empty report): trivy stub was not invoked. argv log:
$(cat "$ARGV_LOG")"
info "case 5 (empty report): OK (embedded JSON error, exit 0, trivy stub invoked)"

# --- Case 6: simulated POST failure -> embedded JSON error, exit 0. ---
reset
make_trivy_stub
SHIM_TRIVY_WRITE_REPORT=1
SHIM_CURL_POST_SUCCEED=0
OUT=$(run_trivy_scan '/' false)
RC=$?
[ "$RC" -eq 0 ] || fail "case 6 (POST failure): expected exit 0 (status embedded), got $RC. stdout: $OUT"
STATUS6=$(printf '%s' "$OUT" | jq -r '.status' 2>/dev/null)
ERROR6=$(printf '%s' "$OUT" | jq -r '.error' 2>/dev/null)
[ "$STATUS6" = "error" ] || fail "case 6 (POST failure): expected status 'error', got: $STATUS6. stdout: $OUT"
case "$ERROR6" in
  *"POST to console failed"*) : ;;
  *) fail "case 6 (POST failure): expected error to mention 'POST to console failed', got: $ERROR6" ;;
esac
info "case 6 (POST failure): OK (embedded JSON error, exit 0)"

# --- Case 7: success path (unset scan_path -> default "/") -> embedded JSON success, exit 0 (regression). ---
reset
make_trivy_stub
SHIM_TRIVY_WRITE_REPORT=1
SHIM_CURL_POST_SUCCEED=1
OUT=$(run_trivy_scan '' false)
RC=$?
[ "$RC" -eq 0 ] || fail "case 7 (success): expected exit 0, got $RC. stdout: $OUT"
STATUS7=$(printf '%s' "$OUT" | jq -r '.status' 2>/dev/null)
SCANNER7=$(printf '%s' "$OUT" | jq -r '.scanner' 2>/dev/null)
CERT7=$(printf '%s' "$OUT" | jq -r '.certname' 2>/dev/null)
[ "$STATUS7" = "scanned" ] || fail "case 7 (success): expected status 'scanned', got: $STATUS7. stdout: $OUT"
[ "$SCANNER7" = "trivy" ] || fail "case 7 (success): expected scanner 'trivy', got: $SCANNER7. stdout: $OUT"
[ "$CERT7" = "test-node.example.com" ] || fail "case 7 (success): expected certname 'test-node.example.com', got: $CERT7. stdout: $OUT"
grep -q '^trivy .*-o ' "$ARGV_LOG" || fail "case 7 (success): trivy stub was not invoked with -o. argv log:
$(cat "$ARGV_LOG")"
info "case 7 (success): OK (embedded JSON success, exit 0, empty scan_path defaulted to '/' without tripping the new guard)"

# --- Case 8: trivy_scan.json schema assertions (AUDIT-03). ---
SENSITIVE8=$(jq -r '.parameters.ingest_token.sensitive' "$TARGET_JSON")
[ "$SENSITIVE8" = "true" ] || fail "case 8 (schema): expected ingest_token.sensitive == true, got: $SENSITIVE8"
TYPE8=$(jq -r '.parameters.scan_path.type' "$TARGET_JSON")
case "$TYPE8" in
  *Pattern*) : ;;
  *) fail "case 8 (schema): expected scan_path.type to contain 'Pattern', got: $TYPE8" ;;
esac
INPUT_METHOD8=$(jq -r '.input_method' "$TARGET_JSON")
[ "$INPUT_METHOD8" = "both" ] || fail "case 8 (schema): expected input_method == 'both', got: $INPUT_METHOD8"
info "case 8 (schema): OK (ingest_token sensitive, scan_path Pattern-typed, input_method both)"

info "all trivy_scan safety cases PASSED"
exit 0
