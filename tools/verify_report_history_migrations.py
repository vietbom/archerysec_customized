"""Verify observation columns without reading or repairing the application DB."""
import os
from pathlib import Path
import sys
import uuid
from importlib import import_module

ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))
os.environ["DJANGO_SETTINGS_MODULE"] = "archerysecurity.settings.test_dashboard"

import django
django.setup()
from django.apps import apps
from django.core.management import call_command
from django.db import connection
from django.db.migrations.state import ProjectState
from projects.models import ProjectDb
from user_management.models import Organization

call_command("migrate", run_syncdb=True, verbosity=0)
before = ProjectState.from_apps(apps)
cases = (
    ("staticscanners", "StaticScansDb", "StaticScanResultsDb", "StaticScanFinding", "0042_report_observed_severity"),
    ("webscanners", "WebScansDb", "WebScanResultsDb", "WebScanFinding", "0033_report_observed_severity"),
)
for label, _, _, link_name, _ in cases:
    before.remove_field(label, link_name.lower(), "observed_severity")
for label, _, _, _, name in cases:
    migration = import_module(label + ".migrations." + name).Migration(name, label)
    with connection.schema_editor() as editor:
        migration.unapply(before.clone(), editor)

org = Organization.objects.create(name="Report history migration")
project = ProjectDb.objects.create(project_name="Application", organization=org)
records = []
for label, scan_name, finding_name, link_name, name in cases:
    Scan = before.apps.get_model(label, scan_name)
    Finding = before.apps.get_model(label, finding_name)
    Link = before.apps.get_model(label, link_name)
    scan = Scan.objects.create(project_id=project.pk, organization_id=org.pk,
        scan_id=uuid.uuid4(), scanner="Trivy" if label == "staticscanners" else "Zap",
        total_vul=76, high_vul=76)
    finding = Finding.objects.create(project_id=project.pk, organization_id=org.pk,
        scan_id=scan.scan_id, vuln_id=uuid.uuid4(), scanner=scan.scanner,
        severity="High", false_positive="Yes", vuln_status="Closed", is_active=False,
        note="Keep analyst review")
    link = Link.objects.create(scan_id=scan.pk, finding_id=finding.pk)
    records.append((label, scan_name, finding_name, link_name, scan.pk, finding.pk, link.pk))
state = before.clone()
for label, _, _, _, name in cases:
    migration = import_module(label + ".migrations." + name).Migration(name, label)
    with connection.schema_editor() as editor:
        state = migration.apply(state, editor)
for label, scan_name, finding_name, link_name, scan_pk, finding_pk, link_pk in records:
    scan = state.apps.get_model(label, scan_name).objects.get(pk=scan_pk)
    finding = state.apps.get_model(label, finding_name).objects.get(pk=finding_pk)
    Link = state.apps.get_model(label, link_name)
    observation = Link.objects.get(pk=link_pk)
    assert (scan.total_vul, scan.high_vul) == (76, 76), "Historical counters must not be repaired"
    assert (finding.false_positive, finding.vuln_status, finding.note) == ("Yes", "Closed", "Keep analyst review")
    assert observation.observed_severity == ""
    observation.observed_severity = "Critical"
    observation.save(update_fields=["observed_severity"])
    assert Link.objects.get(pk=link_pk).observed_severity == "Critical"
for label, _, _, _, name in reversed(cases):
    migration = import_module(label + ".migrations." + name).Migration(name, label)
    with connection.schema_editor() as editor:
        migration.unapply(before.clone(), editor)
print("Report observation migrations: apply, severity storage, preserved old counters/FP/links and rollback passed (isolated SQLite).")
