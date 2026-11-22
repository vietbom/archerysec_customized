"""Atomic imports; only complete scanner snapshots may close absent findings."""
import uuid

from django.db import transaction
from django.utils import timezone

from archeryapi.models import OrgAPIKey
from projects.models import ProjectDb
from scanners.report_formats import ReportValidationError
from scanners.finding_identity import IDENTITY_VERSION
from utility.finding_status import refresh_scan_counts
from utility.scan_history import history_models, remember_finding_scan


@transaction.atomic
def import_findings(findings, result_model, scan_model, project_id, scan_id, request, scanner, scan_url=None, import_warnings=None):
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
    # TH-04: carry a prior decision only from the exact old report observation.
    # This also preserves an old grouped ZAP FP when splitting that exact alert.
    legacy_fp_hashes = set(candidates.filter(identity_version=0, false_positive="Yes").values_list("dup_hash", flat=True))
    _, link_model = history_models(result_model)
    seen = set()
    observed = {}
    for item in findings:
        duplicate_hash = item.duplicate_hash
        require_identity = item.identity_hash
        if not require_identity:
            raise ReportValidationError("The validated finding is missing its versioned identity.")
        record = observed.get(require_identity) or candidates.filter(
            identity_version=IDENTITY_VERSION, identity_hash=require_identity).first()
        if record is None and item.identity_aliases:
            aliases = candidates.filter(identity_version=IDENTITY_VERSION, identity_hash__in=item.identity_aliases)
            if aliases.count() == 1:
                record = aliases.first()
        if record is None and scanner == "Semgrep" and not item.source_enriched:
            # An exact raw-report replay after source enrichment must not create
            # a duplicate or downgrade its source identity back to a position.
            exact = candidates.filter(identity_version=IDENTITY_VERSION, dup_hash=duplicate_hash)
            if exact.count() == 1:
                record = exact.first()
                require_identity = record.identity_hash
        if record is None:
            # Lazy transition: never infer a new identity from formatted text.
            # A v2 row cannot be claimed by another endpoint sharing legacy hash.
            record = candidates.filter(identity_version=0, dup_hash=duplicate_hash).order_by("-false_positive", "pk").first()
        if record is None:
            record = result_model(vuln_id=uuid.uuid4(), project=project, organization=organization, scanner=scanner,
                                  dup_hash=duplicate_hash, jira_ticket="NA")
        else:
            remember_finding_scan(record, record.scan_id)
        false_positive = record.false_positive == "Yes" or duplicate_hash in legacy_fp_hashes
        values = dict(item.values)
        for name, value in values.items():
            setattr(record, name, value)
        # Keep the first legacy hash for audit/transition. identity_hash governs
        # subsequent imports even when severity, text or reference data changes.
        record.dup_hash = record.dup_hash or duplicate_hash
        record.identity_hash = require_identity
        record.identity_version = IDENTITY_VERSION
        record.scan_id = scan_id
        record.date_time = now
        record.false_positive = "Yes" if false_positive else "No"
        record.vuln_status = "Closed" if false_positive else "Open"
        record.is_active = not false_positive
        record.vuln_duplicate = "No"
        record.false_positive_hash = require_identity if false_positive else None
        if record.pk:
            record.save(update_fields=tuple(values) + ("dup_hash", "identity_hash", "identity_version", "scan_id", "date_time", "false_positive",
                "vuln_status", "is_active", "vuln_duplicate", "false_positive_hash", "updated_time"))
        else:
            record.save()
        link_model.objects.get_or_create(scan=scan, finding=record,
                                         defaults={"observed_severity": record.severity or "Low"})
        seen.add(record.pk)
        observed[require_identity] = record
    # A validated complete report is an authoritative snapshot for this scanner
    # in this project, including the legitimate zero-findings report.
    stale = candidates.filter(vuln_status="Open").exclude(false_positive__in=("Yes", "Duplicate")).exclude(
        vuln_duplicate="Yes").exclude(pk__in=seen)
    # Missing findings in a partial scan are not evidence of remediation.
    if import_warnings:
        stale = candidates.none()
    stale.update(vuln_status="Closed", is_active=False)
    # Only the imported report gets new totals; historical observations do not
    # shrink when their canonical findings close or change in a later upload.
    refresh_scan_counts(result_model, scan_model, scan_id, organization)
    updates = {"date_time": now, "scanner": scanner, "scan_status": "100"}
    if scanner == "Semgrep":
        updates["import_warnings"] = import_warnings or []
    if scan_url:
        updates["scan_url"] = scan_url
    scan_model.objects.filter(pk=scan.pk).update(**updates)
    from dashboard.views import trend_update
    from utility.scan_notifications import scan_imported
    trend_update(organization=organization)
    scan.refresh_from_db()
    scan_imported(request, project_id, "OWASP ZAP" if scanner == "Zap" else scanner, scan.total_vul,
                  warnings=import_warnings)
    return scan
