from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("jiraticketing", "0002_auto_20230506_1302"),
    ]

    operations = [
        migrations.AddField(
            model_name="jirasetting",
            name="jira_project_id",
            field=models.CharField(blank=True, max_length=64, null=True),
        ),
        migrations.AddField(
            model_name="jirasetting",
            name="jira_issue_type",
            field=models.CharField(default="Bug", max_length=64),
        ),
    ]