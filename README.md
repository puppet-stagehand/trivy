# trivy — Trivy scanner integration for the Puppet Stagehand Console

Forge: `stagehand-trivy`. Runs [Trivy](https://github.com/aquasecurity/trivy)
against a node's filesystem and POSTs normalized `compliance.v1` results to the
Puppet Stagehand Console's ingest API.

This is a **reference integration**, not the only way in. The console's
ingest endpoint only cares that a batch matches the `compliance.v1` schema
below — bring your own scanner (or your own Trivy wrapper) and skip this
module entirely if you'd rather; just make your adapter emit the same shape.

## Task

`trivy::trivy_scan` — self-contained: the adapter script ships alongside the
task via Bolt's `files` metadata and is resolved through `$PT__installdir`, so
nothing extra needs to be staged on the target.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `console_url` | `String[1]` | — | Console base URL to POST results to (server-injected by the console when it triggers the task). |
| `ingest_token` | `Optional[String[1]]` | — | Bearer token for `/api/v1/compliance/results` (server-injected). |
| `scan_path` | `String[1]` | `/` | Filesystem path Trivy scans (`trivy rootfs`). |
| `install` | `Boolean` | `false` | Install Trivy if it isn't already present on the target. |

Requires `jq` on the target (used by the adapter to build the JSON batch).

## The `compliance.v1` schema

Every scanner integration — this one, `openscap`, or your own — POSTs the
same shape to `$CONSOLE/api/v1/compliance/results`:

```json
{
  "schema_version": "compliance.v1",
  "source": {
    "scanner": "trivy",
    "scanner_version": "<trivy's report SchemaVersion>",
    "adapter_version": "1.0.0"
  },
  "results": [
    {
      "node": "web01.example.com",
      "benchmark_id": "trivy-vuln:app/package-lock.json",
      "control_id": "CVE-2024-12345",
      "status": "fail",
      "severity": "high",
      "timestamp": "2026-08-18T14:03:00Z",
      "remediation_ref": "fixed in 4.2.1",
      "message": "lodash 4.17.15: prototype pollution"
    }
  ]
}
```

**`source`** — `scanner` (required, identifies who produced this batch — use
your own scanner's name if you're not using this module), `scanner_version`
(optional), `adapter_version` (optional, your adapter's own version).

**Each `results[]` entry:**

| Field | Type | Required | Meaning |
|---|---|---|---|
| `node` | string | yes | Certname of the scanned node. |
| `benchmark_id` | string | yes | Which benchmark/target/ruleset this result belongs to. This module uses `trivy-vuln:<target>` and `trivy-misconfig:<target>`. |
| `control_id` | string | yes | The specific control/rule/CVE id (e.g. a CVE id for vulnerabilities, a policy id like `AVD-xxx` for misconfigurations). |
| `status` | enum | yes | `pass` \| `fail` \| `warn` \| `error` \| `not-applicable`. Trivy's adapter only ever emits `pass`, `fail`, or `warn`; the full enum is shared across all scanner integrations, including `openscap`, which uses more of it. |
| `severity` | enum | yes | `low` \| `medium` \| `high` \| `unknown`. This adapter maps Trivy's `CRITICAL`/`HIGH` → `high`, `MEDIUM` → `medium`, `LOW` → `low`, anything else → `unknown`. |
| `timestamp` | string | yes | ISO 8601 UTC. |
| `remediation_ref` | string | no | Fixed version, advisory URL, or resolution text. |
| `message` | string | no | Human-readable detail. |
| `profile_id` | string | no | Not used by this adapter (relevant for profile-driven scanners like OpenSCAP). |

**Ingest contract:**

```
POST $CONSOLE/api/v1/compliance/results
Content-Type: application/json
Authorization: Bearer <ingest_token>   (omit if the endpoint isn't gated)

<the batch object above>
```

The whole batch is one POST — not one result per request. **Empty result
sets are rejected**, so a clean scan with zero findings still needs at least
one synthetic result (this adapter emits a single
`{"status": "pass", "control_id": "no-findings", ...}` entry when Trivy finds
nothing, so the node still reports in — "no findings" is itself a state worth
seeing on the dashboard, and a silently-missing node looks identical to a
node that was never scanned).

## Files

- `tasks/trivy_scan.json` / `tasks/trivy_scan.sh` — the Bolt task.
- `files/trivy-report.sh` — the adapter: Trivy's own JSON report →
  `compliance.v1`. Usable standalone:

  ```sh
  trivy rootfs --scanners vuln --format json -o report.json /
  ./trivy-report.sh --report report.json --certname "$(puppet config print certname)" \
    | curl -sf -X POST "$CONSOLE/api/v1/compliance/results" \
           -H "Authorization: Bearer $(cat /etc/puppetlabs/psh-ingest.token)" \
           -H 'Content-Type: application/json' --data-binary @-
  ```
