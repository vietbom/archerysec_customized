"""Refresh the cached project totals used by the overview dashboard."""
from dashboard.scans_data import scans_query
from projects.models import ProjectDb


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
