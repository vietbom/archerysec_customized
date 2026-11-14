from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("webscanners", "0030_webscanfinding")]
    operations = [
        migrations.AddField(model_name="webscanresultsdb", name="identity_hash",
            field=models.CharField(max_length=64, blank=True, default="", db_index=True)),
        migrations.AddConstraint(model_name="webscanresultsdb", constraint=models.UniqueConstraint(
            fields=("organization", "project", "scanner", "identity_hash"), condition=~models.Q(identity_hash=""),
            name="unique_web_finding_identity")),
    ]
