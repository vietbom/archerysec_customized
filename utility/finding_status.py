"""Keep triage state and scan counters consistent for web and static findings."""
import hashlib

from django.db import transaction
from django.db.models import Case, CharField, Count, F, Q, When
from django.shortcuts import get_object_or_404
from rest_framework import serializers
from utility.scan_history import findings_for_scan, remember_finding_scan


class FindingStatusInput(serializers.Serializer):
    vuln_id = serializers.UUIDField()
    scan_id = serializers.UUIDField()
    false = serializers.ChoiceField(choices=("Yes", "No"))
    status = serializers.ChoiceField(choices=("Open", "Closed"))
    note = serializers.CharField(required=False, allow_blank=True, default="")


def refresh_scan_counts(result_model, scan_model, scan_id, organization):
    scan = scan_model.objects.filter(scan_id=scan_id, organization=organization).first()
    if scan is None:
        return
    if (scan.scanner or "").lower() in ("gitleaks", "semgrep", "trivy", "zap"):
        # Native report totals describe observations, not the remaining open
        # subset. Keep legacy direct memberships before counting report links.
        for finding in result_model.objects.filter(
            scan_id=scan_id, organization=organization, project_id=scan.project_id,
            scanner__iexact=scan.scanner,
        ).exclude(scan_links__scan=scan).iterator():
            remember_finding_scan(finding, scan_id)
        observations = scan.finding_links.filter(
            finding__organization=organization, finding__project_id=scan.project_id,
            finding__scanner__iexact=scan.scanner,
        )
        counted = observations.exclude(finding__false_positive__in=("Yes", "Duplicate")).exclude(
            finding__vuln_duplicate="Yes").annotate(report_severity=Case(
                When(observed_severity="", then=F("finding__severity")),
                default=F("observed_severity"), output_field=CharField(),
            ))
        duplicates = observations.filter(finding__vuln_duplicate="Yes")
    else:
        # Keep the behavior of the other scanner integrations unchanged.
        findings = findings_for_scan(result_model, scan_id, organization)
        counted = findings.filter(vuln_status="Open").exclude(
            false_positive__in=("Yes", "Duplicate")).exclude(vuln_duplicate="Yes").annotate(
                report_severity=F("severity"))
        duplicates = findings.filter(vuln_duplicate="Yes")
    counts = counted.aggregate(
        total_vul=Count("pk"),
        critical_vul=Count("pk", filter=Q(report_severity="Critical")),
        high_vul=Count("pk", filter=Q(report_severity="High")),
        medium_vul=Count("pk", filter=Q(report_severity="Medium")),
        low_vul=Count("pk", filter=Q(report_severity="Low")),
        info_vul=Count("pk", filter=Q(report_severity__in=("Information", "Informational"))),
    )
    counts["total_dup"] = duplicates.count()
    scan_model.objects.filter(pk=scan.pk).update(**counts)


@transaction.atomic
def mark_finding(request, result_model, scan_model):
    form = FindingStatusInput(data=request.data)
    form.is_valid(raise_exception=True)
    data = form.validated_data
    candidates = findings_for_scan(result_model, data["scan_id"], request.user.organization)
    # Lock the canonical row, not the DISTINCT history join (unsupported by PostgreSQL).
    finding = get_object_or_404(
        result_model.objects.select_for_update().filter(pk__in=candidates.values("pk")),
        vuln_id=data["vuln_id"],
    )
    finding.false_positive = data["false"]
    finding.vuln_status = "Closed" if data["false"] == "Yes" else data["status"]
    finding.is_active = finding.vuln_status == "Open"
    finding.note = data["note"]
    finding.updated_by = request.user
    if data["false"] == "Yes":
        # TH-04: the four native importers bind triage to the exact finding
        # identity, never to the broad ZAP title + site + severity key.
        if finding.scanner in ("gitleaks", "Semgrep", "Trivy", "Zap"):
            finding.false_positive_hash = (finding.identity_hash if finding.identity_version == 2 else finding.dup_hash)
        elif hasattr(finding, "fileName"):
            finding.false_positive_hash = finding.dup_hash or hashlib.sha256(
                (str(finding.title) + str(finding.fileName) + str(finding.severity)).encode("utf-8")
            ).hexdigest()
        else:
            finding.false_positive_hash = hashlib.sha256(
                (str(finding.title) + str(finding.url) + str(finding.severity)).encode("utf-8")
            ).hexdigest()
    else:
        finding.false_positive_hash = None
    finding.save(update_fields=("false_positive", "vuln_status", "is_active", "note",
                                "updated_by", "false_positive_hash", "updated_time"))
    refresh_scan_counts(result_model, scan_model, finding.scan_id, finding.organization)
    for scan_id in finding.scan_links.filter(scan__organization=finding.organization).exclude(
        scan__scan_id=finding.scan_id
    ).values_list("scan__scan_id", flat=True).distinct():
        refresh_scan_counts(result_model, scan_model, scan_id, finding.organization)
    if finding.project_id:
        from dashboard.services import refresh_project_summary
        refresh_project_summary(finding.project)
    return finding
