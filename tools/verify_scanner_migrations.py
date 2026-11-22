"""Exercise the new migration DDL/backfill on an isolated in-memory database."""
import os
from pathlib import Path
import sys
import uuid
from importlib import import_module

ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))
os.environ['DJANGO_SETTINGS_MODULE'] = 'archerysecurity.settings.test_dashboard'
import django
django.setup()
from django.apps import apps
from django.core.management import call_command
from django.db import connection, IntegrityError, transaction
from django.db.migrations.state import ProjectState
from projects.models import ProjectDb
from user_management.models import Organization
from staticscanners.models import StaticScanFinding, StaticScanResultsDb, StaticScansDb
from webscanners.models import WebScanResultsDb

call_command('migrate', run_syncdb=True, verbosity=0)
before_version = ProjectState.from_apps(apps)
for label, name in (('staticscanners', 'staticscanresultsdb'), ('webscanners', 'webscanresultsdb')):
    before_version.remove_field(label, name, 'identity_version')
static_version = import_module('staticscanners.migrations.0040_finding_identity_version').Migration('0040_finding_identity_version', 'staticscanners')
web_version = import_module('webscanners.migrations.0032_finding_identity_version').Migration('0032_finding_identity_version', 'webscanners')
with connection.schema_editor() as editor:
    static_version.unapply(before_version, editor)
with connection.schema_editor() as editor:
    web_version.unapply(before_version, editor)
old = before_version.clone()
old.remove_model('staticscanners', 'staticscanfinding')
for label, name in (('staticscanners', 'staticscanresultsdb'), ('webscanners', 'webscanresultsdb')):
    old.models[label, name].options['constraints'] = []
    old.remove_field(label, name, 'identity_hash')
old.clear_delayed_apps_cache()
static_migration = import_module('staticscanners.migrations.0039_finding_identity_and_history').Migration(
    '0039_finding_identity_and_history', 'staticscanners')
web_migration = import_module('webscanners.migrations.0031_finding_identity').Migration('0031_finding_identity', 'webscanners')
with connection.schema_editor() as editor:
    static_migration.unapply(old, editor)
with connection.schema_editor() as editor:
    web_migration.unapply(old, editor)
org = Organization.objects.create(name='Migration test')
project = ProjectDb.objects.create(project_name='Migration project', organization=org)
scan = StaticScansDb.objects.create(project=project, organization=org, scanner='Semgrep', scan_id=uuid.uuid4())
legacy_model = old.apps.get_model('staticscanners', 'StaticScanResultsDb')
legacy = legacy_model.objects.create(project_id=project.pk, organization_id=org.pk, scanner='Semgrep',
    scan_id=scan.scan_id, vuln_id=uuid.uuid4(), false_positive='Yes', vuln_status='Closed', note='Preserve triage')
with connection.schema_editor() as editor:
    after_static = static_migration.apply(old.clone(), editor)
with connection.schema_editor() as editor:
    after_both = web_migration.apply(after_static.clone(), editor)
with connection.schema_editor() as editor:
    after_static_version = static_version.apply(after_both.clone(), editor)
with connection.schema_editor() as editor:
    web_version.apply(after_static_version.clone(), editor)
upgraded = StaticScanResultsDb.objects.get(pk=legacy.pk)
assert upgraded.identity_hash == ''
assert upgraded.identity_version == 0
assert (upgraded.false_positive, upgraded.note) == ('Yes', 'Preserve triage')
assert StaticScanFinding.objects.values_list("scan_id", flat=True).get(finding=upgraded) == scan.pk
for model, name in ((StaticScanResultsDb, 'unique_static_finding_identity'), (WebScanResultsDb, 'unique_web_finding_identity')):
    with connection.cursor() as cursor:
        constraints = connection.introspection.get_constraints(cursor, model._meta.db_table)
    assert constraints[name]['unique']
StaticScanResultsDb.objects.filter(pk=legacy.pk).update(identity_hash='a' * 64)
try:
    with transaction.atomic():
        StaticScanResultsDb.objects.create(project=project, organization=org, scanner='Semgrep',
            scan_id=scan.scan_id, vuln_id=uuid.uuid4(), identity_hash='a' * 64)
except IntegrityError:
    pass
else:
    raise AssertionError('Identity uniqueness was not enforced')
with connection.schema_editor() as editor:
    web_version.unapply(after_static_version, editor)
with connection.schema_editor() as editor:
    static_version.unapply(after_both, editor)
with connection.schema_editor() as editor:
    web_migration.unapply(after_static, editor)
with connection.schema_editor() as editor:
    static_migration.unapply(old, editor)
assert StaticScanFinding._meta.db_table not in connection.introspection.table_names()
assert legacy_model.objects.get(pk=legacy.pk).note == 'Preserve triage'
print('Lifecycle migrations: apply, backfill, preserved triage, uniqueness and rollback passed (isolated SQLite).')

# 0041 adds report completeness warnings without rewriting historical scans.
warnings_migration = import_module('staticscanners.migrations.0041_staticscansdb_import_warnings').Migration(
    '0041_staticscansdb_import_warnings', 'staticscanners')
before_warnings = ProjectState.from_apps(apps)
before_warnings.remove_field('staticscanners', 'staticscansdb', 'import_warnings')
with connection.schema_editor() as editor:
    warnings_migration.unapply(before_warnings, editor)
old_scan_model = before_warnings.apps.get_model('staticscanners', 'StaticScansDb')
assert old_scan_model.objects.filter(pk=scan.pk).exists()
with connection.schema_editor() as editor:
    warnings_migration.apply(before_warnings.clone(), editor)
assert StaticScansDb.objects.get(pk=scan.pk).import_warnings == []
StaticScansDb.objects.filter(pk=scan.pk).update(import_warnings=[{'type': 'PartialParsing', 'path': 'view.html'}])
assert StaticScansDb.objects.get(pk=scan.pk).import_warnings[0]['path'] == 'view.html'
with connection.schema_editor() as editor:
    warnings_migration.unapply(before_warnings, editor)
assert old_scan_model.objects.filter(pk=scan.pk).exists()
print('Semgrep report warnings migration: historical default, JSON round-trip and rollback passed (isolated SQLite).')
