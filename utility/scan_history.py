"""Associate reports with canonical findings without multiplying dashboard rows."""
from django.db import transaction
from django.db.models import Q


def history_models(result_model):
    if result_model._meta.app_label == "webscanners":
        from webscanners.models import WebScanFinding, WebScansDb
        return WebScansDb, WebScanFinding
    from staticscanners.models import StaticScanFinding, StaticScansDb
    return StaticScansDb, StaticScanFinding


def findings_for_scan(result_model, scan_id, organization):
    return result_model.objects.filter(organization=organization).filter(
        Q(scan_id=scan_id) | Q(scan_links__scan__scan_id=scan_id,
                              scan_links__scan__organization=organization)
    ).distinct()


def remember_finding_scan(finding, scan_id):
    scan_model, link_model = history_models(type(finding))
    for scan in scan_model.objects.filter(scan_id=scan_id, project_id=finding.project_id,
                                          organization_id=finding.organization_id):
        link_model.objects.get_or_create(scan=scan, finding=finding,
                                         defaults={"observed_severity": finding.severity or "Low"})


@transaction.atomic
def delete_scans(result_model, scan_ids, organization):
    scan_model, _ = history_models(result_model)
    scans = scan_model.objects.filter(scan_id__in=scan_ids, organization=organization)
    deleted_ids = list(scans.values_list("scan_id", flat=True))
    findings = list(result_model.objects.select_for_update().filter(
        scan_id__in=deleted_ids, organization=organization))
    scans.delete()
    for finding in findings:
        remaining = finding.scan_links.filter(
            scan__organization=organization, scan__project_id=finding.project_id,
        ).select_related("scan").order_by("-scan__pk").first()
        if remaining:
            result_model.objects.filter(pk=finding.pk).update(scan_id=remaining.scan.scan_id)
        else:
            finding.delete()
