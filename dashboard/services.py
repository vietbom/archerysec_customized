"""Refresh the cached project totals used by the overview dashboard."""
from dashboard.scans_data import scans_query
from projects.models import ProjectDb


def native_scanner_summaries(projects):
    """Count canonical findings, independently of report history and scan errors."""
    from django.db.models import Count, F, OuterRef, Q, Subquery
    from django.db.models.functions import Lower
    from staticscanners.models import StaticScanResultsDb, StaticScansDb
    from webscanners.models import WebScanResultsDb, WebScansDb
    from utility.scan_history import findings_for_scan

    projects = list(projects)
    labels = (("gitleaks", "Gitleaks"), ("semgrep", "Semgrep"),
              ("trivy", "Trivy"), ("zap", "OWASP ZAP"))
    fields = ("open", "critical", "high", "medium", "low", "info", "closed", "false_positive")
    rows = {(project.pk, key): dict.fromkeys(fields, 0) | {
        "key": key, "scanner": label, "project": project, "latest_scan": None,
        "warning_count": 0, "report_open": 0, "not_in_latest": 0, "has_reports": False,
        "namespace": "webscanners" if key == "zap" else "staticscanners",
    } for project in projects for key, label in labels}
    for model, scan_model in ((StaticScanResultsDb, StaticScansDb), (WebScanResultsDb, WebScansDb)):
        findings = model.objects.filter(project_id__in=[p.pk for p in projects],
            organization_id=F("project__organization_id"))
        reviewed = ~Q(false_positive__in=("Yes", "Duplicate")) & ~Q(vuln_duplicate="Yes")
        opened = reviewed & Q(vuln_status="Open")
        aggregates = {"open": Count("pk", filter=opened),
            "closed": Count("pk", filter=reviewed & Q(vuln_status="Closed")),
            "false_positive": Count("pk", filter=Q(false_positive="Yes"))}
        for severity in ("Critical", "High", "Medium", "Low"):
            aggregates[severity.lower()] = Count("pk", filter=opened & Q(severity=severity))
        aggregates["info"] = Count("pk", filter=opened & Q(severity__in=("Information", "Informational")))
        # Prefix annotations so false_positive never shadows the text field
        # used by subsequent conditional aggregates.
        for group in findings.annotate(key=Lower("scanner")).values("project_id", "key").annotate(
                **{"count_" + name: aggregate for name, aggregate in aggregates.items()}):
            row = rows.get((group["project_id"], group["key"]))
            if row is not None:
                row.update({field: group["count_" + field] for field in fields})

        latest = scan_model.objects.filter(project_id=OuterRef("project_id"),
            organization_id=OuterRef("organization_id"), scanner__iexact=OuterRef("scanner")).order_by(
                F("date_time").desc(nulls_last=True), "-pk").values("pk")[:1]
        scans = scan_model.objects.filter(project_id__in=[p.pk for p in projects],
            organization_id=F("project__organization_id"), pk=Subquery(latest))
        for scan in scans:
            row = rows.get((scan.project_id, scan.scanner.lower()))
            if row is None:
                continue
            current = findings_for_scan(model, scan.scan_id, scan.organization).filter(vuln_status="Open").exclude(
                false_positive__in=("Yes", "Duplicate")).exclude(vuln_duplicate="Yes")
            row.update(latest_scan=scan, has_reports=True, report_open=current.count(),
                warning_count=len(getattr(scan, "import_warnings", None) or []))
            row["not_in_latest"] = max(0, row["open"] - row["report_open"])
    for row in rows.values():
        # Legacy findings can survive without a corresponding scan row.
        row["not_in_latest"] = max(0, row["open"] - row["report_open"])
    tools = []
    for key, label in labels:
        selected = [row for (_, scanner), row in rows.items() if scanner == key]
        tools.append({"key": key, "scanner": label, **{
            field: sum(row[field] for row in selected) for field in fields},
            "has_reports": any(row["has_reports"] for row in selected),
            "warning_count": sum(row["warning_count"] for row in selected),
            "report_open": sum(row["report_open"] for row in selected),
            "not_in_latest": sum(row["not_in_latest"] for row in selected)})
    incomplete = [row for row in rows.values() if row["warning_count"]]
    return {"rows": list(rows.values()), "tools": tools, "health": {
        "incomplete": incomplete, "warning_count": sum(row["warning_count"] for row in incomplete),
        "project_count": len({row["project"].pk for row in incomplete})}}


def informational_summary(project):
    """Read existing info counts without adding another cached project field."""
    values = {category: counter(project.uu_id, "info") for category, counter in (
        ("static", scans_query.all_static), ("web", scans_query.all_web),
        ("net", scans_query.all_net), ("cloud", scans_query.all_cloud))}
    values["total"] = sum(values.values()) + scans_query.all_manual_scan(project.uu_id, "info")
    return values


def refresh_project_summary(project):
    project_id = project.uu_id
    values = {
        "total_vuln": scans_query.all_vuln(project_id, "total"),
        "total_open": scans_query.all_vuln_count_data(project_id, "Open"),
        "total_close": scans_query.all_vuln_count_data(project_id, "Closed"),
        "total_false": scans_query.all_vuln_count_data(project_id, "false"),
    }
    for severity in ("critical", "high", "medium", "low"):
        values["total_" + severity] = scans_query.all_vuln(project_id, severity)
    for category, query in (("net", scans_query.all_net), ("web", scans_query.all_web),
                            ("static", scans_query.all_static), ("cloud", scans_query.all_cloud)):
        values["total_" + category] = query(project_id, "total")
        for severity in ("critical", "high", "medium", "low"):
            values[severity + "_" + category] = query(project_id, severity)
    ProjectDb.objects.filter(pk=project.pk).update(**values)
    return values
