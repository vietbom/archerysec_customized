from django.db import migrations, models
import django.db.models.deletion


def backfill_current_memberships(apps, schema_editor):
    Scan = apps.get_model("webscanners", "WebScansDb")
    Finding = apps.get_model("webscanners", "WebScanResultsDb")
    Link = apps.get_model("webscanners", "WebScanFinding")
    database = schema_editor.connection.alias
    # Only known relationships can be recovered; never guess from scan totals.
    for scan in Scan.objects.using(database).filter(scanner__iexact="Zap").iterator():
        ids = Finding.objects.using(database).filter(
            scan_id=scan.scan_id, organization_id=scan.organization_id,
            project_id=scan.project_id, scanner__iexact="Zap",
        ).values_list("pk", flat=True)
        batch = []
        for finding_id in ids.iterator():
            batch.append(Link(scan_id=scan.pk, finding_id=finding_id))
            if len(batch) == 500:
                Link.objects.using(database).bulk_create(batch)
                batch = []
        if batch:
            Link.objects.using(database).bulk_create(batch)


class Migration(migrations.Migration):
    dependencies = [("webscanners", "0029_auto_20230506_1302")]

    operations = [
        migrations.CreateModel(
            name="WebScanFinding",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("finding", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,
                                             related_name="scan_links", to="webscanners.webscanresultsdb")),
                ("scan", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,
                                          related_name="finding_links", to="webscanners.webscansdb")),
            ],
        ),
        migrations.AddConstraint(
            model_name="webscanfinding",
            constraint=models.UniqueConstraint(fields=("scan", "finding"), name="unique_web_scan_finding"),
        ),
        migrations.RunPython(backfill_current_memberships, migrations.RunPython.noop),
    ]
