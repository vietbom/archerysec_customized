from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("webscanners", "0031_finding_identity")]
    operations = [migrations.AddField(
        model_name="webscanresultsdb", name="identity_version",
        field=models.PositiveSmallIntegerField(default=0),
    )]
