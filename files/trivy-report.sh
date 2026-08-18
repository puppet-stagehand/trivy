#!/usr/bin/env bash
# trivy-report.sh — Trivy adapter: JSON report → compliance.v1
#
# Vulnerabilities and misconfigurations map onto the normalized schema:
#   control_id   = CVE id (vulns) / policy id like AVD-xxx (misconfigs)
#   benchmark_id = "trivy-vuln:<target>" / "trivy-misconfig:<target>"
#   status       = fail for open vulns; misconfig PASS/FAIL map directly
#   severity     = CRITICAL,HIGH → high · MEDIUM → medium · LOW → low · else unknown
#   remediation  = fixed version / primary URL / resolution text
#
#   trivy rootfs --scanners vuln --format json -o report.json /
#   ./trivy-report.sh --report report.json --certname "$(puppet config print certname)" \
#     | curl -sf -X POST "$CONSOLE/api/v1/compliance/results" \
#            -H "Authorization: Bearer $(cat /etc/puppetlabs/pcc-ingest.token)" \
#            -H 'Content-Type: application/json' --data-binary @-
#
# Note: a clean scan emits one synthetic "pass" control per target so the node
# still reports in (the ingestion endpoint rejects empty result sets, and
# "no findings" is itself a state worth seeing on the dashboard).
set -euo pipefail

REPORT="" CERTNAME="$(hostname -f 2>/dev/null || hostname)"
while [ $# -gt 0 ]; do
  case "$1" in
    --report) REPORT="$2"; shift 2 ;;
    --certname) CERTNAME="$2"; shift 2 ;;
    *) echo "usage: $0 --report <trivy.json> [--certname <name>]" >&2; exit 2 ;;
  esac
done
[ -n "$REPORT" ] && [ -r "$REPORT" ] || { echo "readable --report <trivy.json> is required" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

jq --arg node "$CERTNAME" '
  def sev: {CRITICAL:"high", HIGH:"high", MEDIUM:"medium", LOW:"low"}[.] // "unknown";
  def ts: (now | todate);

  {
    schema_version: "compliance.v1",
    source: { scanner: "trivy", scanner_version: (.SchemaVersion|tostring), adapter_version: "1.0.0" },
    results: ([ .Results[]? as $r |
      (
        ($r.Vulnerabilities // [] | map({
          node: $node,
          benchmark_id: ("trivy-vuln:" + ($r.Target // "unknown")),
          control_id: .VulnerabilityID,
          status: "fail",
          severity: (.Severity | sev),
          timestamp: ts,
          remediation_ref: (if .FixedVersion then ("fixed in " + .FixedVersion) else (.PrimaryURL // "") end),
          message: ((.PkgName // "") + " " + (.InstalledVersion // "") + ": " + (.Title // .VulnerabilityID))
        })) +
        ($r.Misconfigurations // [] | map({
          node: $node,
          benchmark_id: ("trivy-misconfig:" + ($r.Target // "unknown")),
          control_id: .ID,
          status: (if .Status == "FAIL" then "fail" elif .Status == "PASS" then "pass" else "warn" end),
          severity: (.Severity | sev),
          timestamp: ts,
          remediation_ref: (.PrimaryURL // ""),
          message: (.Title // .ID)
        }))
      )
    ] | flatten)
  }
  | if (.results | length) == 0 then
      .results = [{
        node: $node, benchmark_id: "trivy-vuln:clean", control_id: "no-findings",
        status: "pass", severity: "unknown", timestamp: ts,
        message: "trivy reported no findings"
      }]
    else . end
' "$REPORT"
