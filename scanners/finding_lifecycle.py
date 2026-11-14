"""Atomic full-snapshot imports scoped to one project/branch and scanner."""
import uuid

from django.db import transaction
from django.utils import timezone

from archeryapi.models import OrgAPIKey
from projects.models import ProjectDb
from scanners.report_formats import ReportValidationError
from utility.finding_status import refresh_scan_counts
from utility.scan_history import history_models, remember_finding_scan


@transaction.atomic
def import_findings(findings, result_model, scan_model, project_id, scan_id, request, scanner, scan_url=None):
    # The project is the branch boundary chosen by this deployment. Serializing
    # imports also prevents two concurrent uploads from both creating a finding.
    if request.user.is_authenticated:
        organization = request.user.organization
    else:
        key = OrgAPIKey.objects.filter(api_key=request.META.get("HTTP_X_API_KEY"), is_active=True).first()
        if key is None:
            raise ReportValidationError("An active organization API key is required.")
        organization = key.organization
    project = ProjectDb.objects.select_for_update().get(pk=project_id, organization=organization)
    scan = scan_model.objects.get(scan_id=scan_id, project=project)
    # Legacy API uploads create scans with the default organization. Assign the
    # authenticated organization before recording the report relationships.
    scan.organization = organization
    scan.save(update_fields=("organization",))
    now = timezone.now()
    candidates = result_model.objects.filter(project=project, organization=organization, scanner=scanner)
    _, link_model = history_models(result_model)
    seen = set()
    observed = {}
    for item in findings:
        duplicate_hash = item.duplicate_hash
        # dup_hash is authoritative again, even for rows previously imported with
        # identity_hash. Retain that unused column for schema/data compatibility.
        record = observed.get(duplicate_hash) or candidates.filter(dup_hash=duplicate_hash).order_by("pk").first()
        if record is None:
            record = result_model(vuln_id=uuid.uuid4(), project=project, organization=organization, scanner=scanner,
                                  dup_hash=duplicate_hash, jira_ticket="NA")
        else:
            remember_finding_scan(record, record.scan_id)
        false_positive = record.false_positive == "Yes" or candidates.filter(
            false_positive="Yes", false_positive_hash=item.suppression_hash or duplicate_hash,
        ).exists()
        values = dict(item.values)
        for name, value in values.items():
            setattr(record, name, value)
        record.dup_hash = duplicate_hash
        record.scan_id = scan_id
        record.date_time = now
        record.false_positive = "Yes" if false_positive else "No"
        record.vuln_status = "Closed" if false_positive else "Open"
        record.is_active = not false_positive
        record.vuln_duplicate = "No"
        if false_positive and not record.false_positive_hash:
            record.false_positive_hash = item.suppression_hash or record.dup_hash
        if record.pk:
            record.save(update_fields=tuple(values) + ("dup_hash", "scan_id", "date_time", "false_positive",
                "vuln_status", "is_active", "vuln_duplicate", "false_positive_hash", "updated_time"))
        else:
            record.save()
        link_model.objects.get_or_create(scan=scan, finding=record)
        seen.add(record.pk)
        observed[duplicate_hash] = record
    # A validated complete report is an authoritative snapshot for this scanner
    # in this project, including the legitimate zero-findings report.
    candidates.filter(vuln_status="Open").exclude(false_positive__in=("Yes", "Duplicate")).exclude(
        vuln_duplicate="Yes").exclude(pk__in=seen).update(vuln_status="Closed", is_active=False)
    refresh_scan_counts(result_model, scan_model, scan_id, organization)
    updates = {"date_time": now, "scanner": scanner, "scan_status": "100"}
    if scan_url:
        updates["scan_url"] = scan_url
    scan_model.objects.filter(pk=scan.pk).update(**updates)
    from dashboard.views import trend_update
    from utility.scan_notifications import scan_imported
    trend_update(organization=organization)
    scan.refresh_from_db()
    scan_imported(request, project_id, "OWASP ZAP" if scanner == "Zap" else scanner, scan.total_vul)
    return scan
