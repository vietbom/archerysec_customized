# Four-scanner upload and lifecycle audit — historical rollback policy

> **Superseded on 2026-11-17.** The full text below describes the earlier
> rollback, not the current implementation. Current identity v2, endpoint-based
> ZAP findings, false-positive scope, new migrations and thesis changes are in
> [scanner-upgrade-2026-11-17.md](scanner-upgrade-2026-11-17.md).
> Native formats and the complete-snapshot organization/project/scanner boundary
> remain unchanged. Use `audit_scanner_identity` after applying the version-marker
> migrations to inspect unconverted legacy rows. Historical diagrams remain
> labeled as pre-v2 teaching aids in their README.

The comparison boundary is **organization + ArcherySec project + scanner**.
In this deployment each project represents one branch, as requested. Each
accepted upload must be a complete scan of that branch using consistent rules,
targets and filters. Findings absent from the new snapshot are automatically
closed only within that boundary.

## Supported native inputs

| Tool | Upload format | Finding identity |
| --- | --- | --- |
| Gitleaks | JSON array; `[]` or native `null` for zero findings | Original SHA-256 of scanner + native Fingerprint, or scanner/rule/file/start line/commit when absent |
| Semgrep | JSON with a results array | Original scanner/check_id/severity/path/message/metadata/end/lines payload |
| Trivy | Native JSON for container_image, filesystem, repository and rootfs | Original per-kind payload, including versions/title/severity/target for vulnerabilities, and content/location fields for secrets/configuration |
| OWASP ZAP | Traditional XML with named sites and alerts elements | Original scanner/title/severity/site URL/alert/instances/description/raw reference payload |

Trivy reads every vulnerability, secret and misconfiguration across result
sections, including nullable lists and reports with mixed finding types. Passing
or excepted configuration checks and Semgrep explicitly ignored results are not
open findings. ZAP handles each site separately and retains each alert's
instances, without merging different instance sets by site/rule. The original
fingerprints from the submitted implementation are authoritative in `dup_hash`.
Changing fields included in that payload can create a new finding and close the
old one. Informational Semgrep/ZAP findings are displayed as Informational, but
their hash uses the original Low mapping for compatibility. Reference display
formatting does not change the source values used in the fingerprint.

See [legacy-fingerprint-restoration.md](legacy-fingerprint-restoration.md) for
the restored fields and transition behavior.

Reference formats were checked against the official
[Gitleaks reporting documentation](https://github.com/gitleaks/gitleaks#reporting),
[Semgrep JSON fields](https://docs.semgrep.dev/semgrep-appsec-platform/json-and-sarif),
[Trivy reporting documentation](https://trivy.dev/docs/latest/configuration/reporting/)
and [ZAP Traditional XML example](https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-xml/).
SARIF, GitLab SAST wrappers, ZAP JSON/HTML and arbitrary custom JSON schemas are
not accepted by these four native importers.

## Lifecycle and counts

| Complete report | Open findings | Closed findings | Canonical stored rows |
| --- | --- | --- | --- |
| A, B | A, B | none | 2 |
| B, C, C (same identity repeated) | B, C | A | 3 |
| C | C | A, B | 3 |
| A, B, C | A, B, C | none | 3 |
| Empty valid report | none | A, B, C | 3 |
| A, B, C again | A, B, C | none | 3 |

An existing finding retains its UUID, original creation time, notes and Jira
link. A finding closed either automatically or manually returns to Open when
the next complete report detects it again. There is no separate Re-open status:
reopening means the existing Closed record becomes Open.

False Positive = Yes is a persistent analyst decision: these findings stay
Closed and excluded from open/severity totals through absence and reappearance.
Removing that decision permits subsequent detections to reopen the finding.

Dashboard/project totals count canonical currently open findings, excluding
false positives and duplicate records. API upload summaries use the same
eligibility rules. Report-to-finding associations allow both old and new reports
to be viewed without cloning findings. These associations share current finding
content and triage; they are not immutable historical status snapshots.

Validation runs before updates. Invalid layouts, malformed finding records and
Semgrep execution errors reject the import, roll back its new scan row, and do
not close existing findings. A valid empty report closes the previous open
findings. Imports lock the project and use a conditional database uniqueness
constraint to protect finding identity against concurrent imports. Functional
and migration checks use isolated SQLite; concurrent PostgreSQL execution has
not been load tested.

## Corrections found during this audit

- The intermediate stable-identity redesign has been reverted at the user's
  request: Semgrep/Trivy/ZAP retain the original metadata-sensitive fingerprints.
- Trivy previously skipped filesystem vulnerabilities and read only the first
  secret in a result.
- Empty objects and unrelated XML could be accepted as zero-finding snapshots;
  Semgrep execution errors could also close existing findings.
- Static scanner reports lost their finding lists after repeated uploads.
- XML loading stripped non-ASCII characters, and API summaries counted false
  positives as active findings.
- API project lookup did not restrict uploads to the API key's organization.

## Deployment and legacy data

Apply migrations before serving the updated code:

```powershell
python manage.py migrate
```

Existing migrations: `staticscanners.0039_finding_identity_and_history` and
`webscanners.0031_finding_identity` (which depends on the previously added ZAP
history migration). They add identity fields, uniqueness constraints and static
report associations. They preserve existing UUIDs and triage. Restoring the
original fingerprints adds no migration and does not drop the intermediate
`identity_hash` column or its existing values. Imports no longer read/write that
column for identity: matching `dup_hash` reuses rows regardless of whether they
carry an intermediate identity. Missing latest report associations are remembered
before moving scan_id. Already lost earlier associations cannot be inferred safely.
Rows previously merged across different original payloads cannot be split into
historical observations without the original reports. Stored dup_hash values
remain unchanged; unmatched incoming hashes follow the normal create/close flow.

Automation reflects the supplied report. A finding absent because scan rules,
severity filters or targets changed is indistinguishable from one no longer
detected. Keep these settings consistent. Semgrep uses its original end/lines
payload even when the report includes a native match ID. Gitleaks
fingerprints for historical Git scans may include commit identity.

The local `gitlab-ci-templates/templates/trivy-sca.yml` runs Trivy with
`--severity HIGH,CRITICAL --ignore-unfixed`. Its uploaded reports therefore do
not contain lower severities or vulnerabilities without a published fix. This
audit does not change those CI filters. The user confirmed that GitLab owns
Security Gates and routes different branches/environments to separate ArcherySec
projects. Those settings are outside this restoration's scope. The importer
expects ZAP Traditional XML.

## Verification

```powershell
.venv\Scripts\python.exe manage.py test scanners.test_legacy_fingerprints scanners.test_finding_lifecycle dashboard.test_regressions archerysecurity.test_references archerysecurity.test_scanner_references webscanners.test_zap_reimport --settings=archerysecurity.settings.test_dashboard --noinput
.venv\Scripts\python.exe tools\verify_scanner_migrations.py
```

These tests cover multipart UI and API uploads, shared/new identities,
open/closed/reopen transitions, empty snapshots, false-positive persistence,
original metadata-sensitive identity, native Semgrep IDs not overriding that
identity, multiple ZAP sites and distinct instance sets, mixed Trivy result
sections, rollback, organization/project/tool
boundaries, report deletion/history, references, notifications and dashboards.
Golden fixtures capture 11 hashes from the original parser functions, including
INFO mapping, raw/nested references and instance markup. Transition tests cover
both blank and populated intermediate identity_hash values without losing UUID,
triage, ticket links or report memberships.
The migration verifier separately checks schema apply/rollback, membership
backfill, preservation of triage and enforcement of finding identity uniqueness.
Both commands use isolated temporary databases and never migrate the configured
application database.
