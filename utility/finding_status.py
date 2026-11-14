"""Keep triage state and scan counters consistent for web and static findings."""
import hashlib

from django.db import transaction
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404
from rest_framework import serializers
from utility.scan_history import findings_for_scan


class FindingStatusInput(serializers.Serializer):
    vuln_id = serializers.UUIDField()
    scan_id = serializers.UUIDField()
    false = serializers.ChoiceField(choices=("Yes", "No"))
    status = serializers.ChoiceField(choices=("Open", "Closed"))
    note = serializers.CharField(required=False, allow_blank=True, default="")


def refresh_scan_counts(result_model, scan_model, scan_id, organization):
    findings = findings_for_scan(result_model, scan_id, organization)
    active = findings.filter(vuln_status="Open").exclude(
        false_positive__in=("Yes", "Duplicate")
    ).exclude(vuln_duplicate="Yes")
    counts = active.aggregate(
        total_vul=Count("pk"),
        critical_vul=Count("pk", filter=Q(severity="Critical")),
        high_vul=Count("pk", filter=Q(severity="High")),
        medium_vul=Count("pk", filter=Q(severity="Medium")),
        low_vul=Count("pk", filter=Q(severity="Low")),
        info_vul=Count("pk", filter=Q(severity__in=("Information", "Informational"))),
    )
    counts["total_dup"] = findings.filter(vuln_duplicate="Yes").count()
    scan_model.objects.filter(scan_id=scan_id, organization=organization).update(**counts)


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
        # Static parsers use the finding fingerprint; legacy web parsers use
        # title + URL + severity. ZAP supports this legacy suppression key too.
        if hasattr(finding, "fileName"):
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
