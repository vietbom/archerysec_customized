# Dashboard UI, false-positive triage and notifications

The overview and project dashboards share responsive white statistic cards, severity
colors and chart sizing. Project scan tables are grouped into keyboard-accessible
tabs. Zero open findings no longer hide the overview's false-positive/closed counts.

## Triage behavior

- Marking a finding false positive closes it, removes it from open/severity totals,
  and increases the False Positive counter. It is excluded from the Closed counter,
  which tracks remediated findings.
- Restoring a finding clears its suppression key and reopens it. Both scan counts
  (including Critical) and cached project totals update in the same transaction.
- Gitleaks, Semgrep, Trivy and ZAP retain false-positive decisions when the same
  fingerprint is imported again. Static suppression lookups are scoped by project,
  scanner and organization. Existing scanner fingerprint definitions are retained.
- Dashboard counters link to lists using the same open/closed/false-positive
  filters. False-positive lists explicitly label these findings.
- Static/web triage dialogs have unique IDs per finding. The UI checks role names
  rather than assuming the Analyst role has database ID 2.

Previously Semgrep and Trivy overwrote the flag on reimport; marking used a
different static suppression hash from the parsers, retained stale suppression
keys on restore, and omitted Critical from scan count updates. Closed counts
previously included false positives. Monthly trend snapshots now use each
project's totals and organization.

## Notifications

The bell requests the signed-in user's unread inbox when the page loads, when it
opens, and every 30 seconds while the page is visible. It works on pages that do
not pass a `message` context variable. Marking one/all notifications read requires
a CSRF-protected POST and affects only that recipient; records are preserved.

Importing the four supported scanner reports creates an in-app completion notice
without requiring SMTP. Browser uploads notify the uploader; API uploads notify
active Admin/Analyst users and superusers in the project's organization. Existing
direct scan-start/completion producers are retained.

Previously the unread list was not recipient-scoped, most imports only sent email,
the live badge was not initialized, deleting one notification used a nonexistent
`organization` field, and Clear All deleted other users' notifications too.

The shared page also loads Bootstrap before bootstrap-select. The overview no
longer loads a second jQuery version after initializing its charts.

## References for Gitleaks, Semgrep, Trivy and OWASP ZAP

These four importers store reference fields as deduplicated JSON lists. Gitleaks
reads the report's `References`/`Reference` and `Link` fields when present. Semgrep
reads references and rule-source links from `extra.metadata`, plus
`extra.references`. Trivy reads `References` and `PrimaryURL` for vulnerabilities,
secrets and misconfigurations. ZAP supports both CDATA and nested HTML inside its
XML `reference` element. Its existing fingerprint uses the raw reference text so
normalizing stored links does not reset triage decisions for existing findings.

The detail pages render each URL as an individual external link. Historical
Python list strings, JSON lists and HTML references remain readable. Reports
without reference URLs do not get invented links. Older Gitleaks/Semgrep rows
whose reference fields were never saved need reimporting to populate those
fields; no database migration is required.

## Repeated ZAP uploads

ZAP keeps one canonical finding for dashboard counts and triage, with a
`WebScanFinding` association for every report containing it. Imports remember the
previous association before updating the canonical finding's latest scan ID.
Both report lists and grouped findings read these associations; special
characters in alert titles are URL-encoded. False-positive decisions remain
shared, and changing triage refreshes the counters of linked reports. Deleting
one report preserves findings still used by another report.

Apply the schema change before starting the updated application:

```powershell
python manage.py migrate
```

Migration `webscanners.0030_webscanfinding` backfills known current ZAP report
relationships. Relationships already lost by earlier imports cannot be inferred
reliably from stored totals. Reupload the original XML to create a readable new
report; this does not reconstruct an already empty historical report. These
associations share current finding content and triage, rather than storing an
immutable snapshot of past status.

## Verification

The subsequent four-scanner lifecycle audit adds static report history and
validation of full scan snapshots. Original scanner fingerprints have been
restored in dup_hash; the intermediate identity_hash is retained only for schema
compatibility. See
[four-scanner-lifecycle.md](four-scanner-lifecycle.md) for the required migrations,
comparison scope, legacy-data limitations and the complete regression command.

Run functional regressions with:

```powershell
.venv\Scripts\python.exe manage.py test dashboard.test_regressions archerysecurity.test_references archerysecurity.test_scanner_references webscanners.test_zap_reimport --settings=archerysecurity.settings.test_dashboard --noinput
```

The test settings use a temporary in-memory SQLite database and current model
schemas, bypassing historical migrations that import optional scanner packages.
No application data or external scanner/Jira/email services are used.

Optional browser verification (Playwright plus an installed Chrome):

```powershell
.venv\Scripts\python.exe tools\verify_dashboard_ui.py
```

Set `ARCHERY_BROWSER_EXECUTABLE` to use another Chromium installation. The script
uses the same isolated database, checks tabs, notifications and mobile overflow,
and writes screenshots/results to `.artifacts/dashboard-ui/` (ignored by Git).
The existing shared page still needs access to its jQuery CDN.

Deploy the changed templates, Python modules and static assets together using the
normal application deployment process, applying the ZAP history migration above. This
change does not infer or restore false-positive decisions already overwritten by
older imports; those findings need review again. Existing historical monthly
totals are not reconstructed.
