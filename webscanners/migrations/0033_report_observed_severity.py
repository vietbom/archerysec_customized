from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("webscanners", "0032_finding_identity_version")]
    operations = [
        migrations.AddField(
            model_name="webscanfinding", name="observed_severity",
            field=models.CharField(max_length=32, blank=True, default=""),
        ),
    ]
