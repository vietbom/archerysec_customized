"""Read-only migration inventory; never guess identities from descriptions."""
import json
import uuid

from django.core.management.base import BaseCommand
from django.db.models import Count, Q

from staticscanners.models import StaticScanResultsDb
from webscanners.models import WebScanResultsDb


class Command(BaseCommand):
    help = "Read-only counts of legacy/v2 findings and unconverted FP decisions for the four native scanners."

    def add_arguments(self, parser):
        parser.add_argument("--project", type=uuid.UUID, help="Optional ArcherySec project UUID")

    def handle(self, *args, **options):
        groups = []
        for model, scanners in ((StaticScanResultsDb, ("gitleaks", "Semgrep", "Trivy")), (WebScanResultsDb, ("Zap",))):
            query = model.objects.filter(scanner__in=scanners)
            if options["project"]:
                query = query.filter(project__uu_id=options["project"])
            groups.extend(query.values("organization_id", "project_id", "scanner", "identity_version").annotate(
                findings=Count("pk"), false_positives=Count("pk", filter=Q(false_positive="Yes")),
            ).order_by("organization_id", "project_id", "scanner", "identity_version"))
        self.stdout.write(json.dumps({"read_only": True, "groups": groups,
            "legacy_findings": sum(row["findings"] for row in groups if row["identity_version"] == 0),
            "legacy_fp": sum(row["false_positives"] for row in groups if row["identity_version"] == 0)}, indent=2))
