"""Refresh the cached project totals used by the overview dashboard."""
from dashboard.scans_data import scans_query
from projects.models import ProjectDb


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
