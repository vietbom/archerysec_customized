from django.db import migrations, models
import django.db.models.deletion


def backfill_memberships(apps, schema_editor):
    Scan = apps.get_model("staticscanners", "StaticScansDb")
    Finding = apps.get_model("staticscanners", "StaticScanResultsDb")
    Link = apps.get_model("staticscanners", "StaticScanFinding")
    database = schema_editor.connection.alias
    for scan in Scan.objects.using(database).filter(scanner__in=("gitleaks", "Semgrep", "Trivy")).iterator():
        ids = Finding.objects.using(database).filter(scan_id=scan.scan_id, project_id=scan.project_id,
            organization_id=scan.organization_id, scanner=scan.scanner).values_list("pk", flat=True)
        batch = []
        for finding_id in ids.iterator():
            batch.append(Link(scan_id=scan.pk, finding_id=finding_id))
            if len(batch) == 500:
                Link.objects.using(database).bulk_create(batch)
                batch = []
        if batch:
            Link.objects.using(database).bulk_create(batch)


class Migration(migrations.Migration):
    dependencies = [("staticscanners", "0038_auto_20230506_1302")]
    operations = [
        migrations.AddField(model_name="staticscanresultsdb", name="identity_hash",
            field=models.CharField(max_length=64, blank=True, default="", db_index=True)),
        migrations.AddConstraint(model_name="staticscanresultsdb", constraint=models.UniqueConstraint(
            fields=("organization", "project", "scanner", "identity_hash"), condition=~models.Q(identity_hash=""),
            name="unique_static_finding_identity")),
        migrations.CreateModel(name="StaticScanFinding", fields=[
            ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
            ("finding", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,
                related_name="scan_links", to="staticscanners.staticscanresultsdb")),
            ("scan", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,
                related_name="finding_links", to="staticscanners.staticscansdb")),
        ]),
        migrations.AddConstraint(model_name="staticscanfinding", constraint=models.UniqueConstraint(
            fields=("scan", "finding"), name="unique_static_scan_finding")),
        migrations.RunPython(backfill_memberships, migrations.RunPython.noop),
    ]
