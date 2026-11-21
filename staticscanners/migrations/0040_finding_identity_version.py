from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("staticscanners", "0039_finding_identity_and_history")]
    operations = [migrations.AddField(
        model_name="staticscanresultsdb", name="identity_version",
        field=models.PositiveSmallIntegerField(default=0),
    )]
