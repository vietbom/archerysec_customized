import logging

from django.conf import settings
from django.core import signing
from jira import JIRA
from jira.exceptions import JIRAError

from cloudscanners.models import CloudScansResultsDb
from jiraticketing.models import JiraSyncJob, jirasetting
from networkscanners.models import NetworkScanResultsDb
from staticscanners.models import StaticScanResultsDb
from webscanners.models import WebScanResultsDb

logger = logging.getLogger(__name__)

SCANNER_RESULT_MODELS = {
    "gitleaks": (StaticScanResultsDb, "gitleaks"),
    "semgrep": (StaticScanResultsDb, "Semgrep"),
    "semgrepscan": (StaticScanResultsDb, "Semgrep"),
    "trivy": (StaticScanResultsDb, "Trivy"),
    "zap": (WebScanResultsDb, "Zap"),
    "zap_scan": (WebScanResultsDb, "Zap"),
    "web": (WebScanResultsDb, None),
    "sast": (StaticScanResultsDb, None),
    "network": (NetworkScanResultsDb, None),
    "cloud": (CloudScansResultsDb, None),
}


class JiraConfigurationError(Exception):
    pass


def get_jira_configuration(organization):
    organization_id = getattr(organization, "pk", organization)
    config = (
        jirasetting.objects.filter(organization_id=organization_id, is_active=True)
        .order_by("-created_time")
        .first()
    )
    if config is None:
        return None

    try:
        username = signing.loads(config.jira_username) if config.jira_username else ""
        password = signing.loads(config.jira_password) if config.jira_password else ""
    except signing.BadSignature as error:
        raise JiraConfigurationError(
            "Stored Jira credentials cannot be decoded"
        ) from error

    return {
        "setting": config,
        "server": config.jira_server,
        "username": username,
        "password": password,
        "project_id": config.jira_project_id
        or getattr(settings, "JIRA_DEFAULT_PROJECT_ID", ""),
        "issue_type": config.jira_issue_type
        or getattr(settings, "JIRA_DEFAULT_ISSUE_TYPE", "")
        or "Bug",
    }


def _build_jira_client(server, username, password):
    if not server or not password:
        raise JiraConfigurationError("Jira server URL and API token are required")

    options = {"server": server}
    if username:
        return JIRA(
            options,
            basic_auth=(username, password),
            max_retries=0,
            timeout=30,
        )
    return JIRA(options, token_auth=password, max_retries=0, timeout=30)


def get_jira_client(organization):
    config = get_jira_configuration(organization)
    if config is None:
        raise JiraConfigurationError("Jira is not configured for this organization")
    return _build_jira_client(
        config["server"], config["username"], config["password"]
    )


def get_jira_projects(organization):
    return get_jira_client(organization).projects()


def _resolve_destination_project(client, config):
    project_id = config["project_id"]
    if project_id:
        return project_id

    projects = client.projects()
    if len(projects) != 1:
        raise JiraConfigurationError(
            "Jira destination project ID is not configured and %d projects are available"
            % len(projects)
        )

    project = projects[0]
    project_id = getattr(project, "id", None) or getattr(project, "key", None)
    if not project_id:
        raise JiraConfigurationError("The Jira destination project has no ID or key")

    setting = config["setting"]
    setting.jira_project_id = project_id
    setting.save(update_fields=["jira_project_id", "created_time"])
    return project_id


def validate_jira_connection(server, username, password):
    return _build_jira_client(server, username, password).projects()


def _resolve_issue_type(client, project_id, requested_issue_type, config):
    metadata = client.createmeta(
        projectIds=str(project_id), expand="projects.issuetypes"
    )
    projects = metadata.get("projects", [])
    issue_types = projects[0].get("issuetypes", []) if projects else []
    if not issue_types:
        raise JiraConfigurationError(
            "No createable Jira issue types are available for project %s"
            % project_id
        )

    requested = str(requested_issue_type or "").strip().lower()
    selected = next(
        (
            issue_type
            for issue_type in issue_types
            if str(issue_type.get("id", "")).lower() == requested
            or str(issue_type.get("name", "")).lower() == requested
        ),
        None,
    )
    if selected is None:
        selected = next(
            (
                issue_type
                for issue_type in issue_types
                if str(issue_type.get("name", "")).lower() == "task"
            ),
            None,
        )
    if selected is None:
        selected = next(
            (issue_type for issue_type in issue_types if not issue_type.get("subtask")),
            issue_types[0],
        )

    config_setting = config["setting"]
    selected_id = str(selected.get("id") or selected.get("name"))
    if config_setting.jira_issue_type != selected_id:
        config_setting.jira_issue_type = selected_id
        config_setting.save(update_fields=["jira_issue_type", "created_time"])
    return selected_id


def _scanner_result_model(scanner):
    scanner_key = (scanner or "").strip().lower()
    try:
        return SCANNER_RESULT_MODELS[scanner_key]
    except KeyError as error:
        raise JiraConfigurationError(
            "No Jira finding model is registered for scanner %r" % scanner
        ) from error


def _finding_target(finding):
    if isinstance(finding, WebScanResultsDb):
        return finding.url
    if isinstance(finding, NetworkScanResultsDb):
        return "%s:%s" % (finding.ip, finding.port)
    if isinstance(finding, CloudScansResultsDb):
        return "%s (%s)" % (finding.resourceName, finding.resourceId)
    return finding.filePath or finding.fileName


def _finding_description(finding, scan_id=None):
    archery_project = getattr(finding, "project", None)
    parts = [
        finding.description or "",
        "ArcherySec project: %s (ID: %s)"
        % (
            getattr(archery_project, "project_name", "Unknown"),
            getattr(finding, "project_id", "Unknown"),
        ),
        "Scanner: %s" % (finding.scanner or "Unknown"),
        "Severity: %s" % (finding.severity or "Unknown"),
        "Target: %s" % (_finding_target(finding) or "Unknown"),
    ]
    if finding.solution:
        parts.append("Remediation: %s" % finding.solution)
    references = getattr(finding, "references", None) or getattr(
        finding, "reference", None
    )
    if references:
        parts.append("References: %s" % references)
    if finding.dup_hash:
        parts.append("Fingerprint: %s" % finding.dup_hash)
    if scan_id:
        parts.append("ArcherySec scan: %s" % scan_id)
    return "\n\n".join(parts)


def process_finding(
    finding,
    jira_client=None,
    jira_project_id=None,
    issue_type=None,
    scan_id=None,
    summary=None,
    description=None,
):
    """Create one Jira issue per finding, then comment when it reappears."""
    try:
        config = get_jira_configuration(finding.organization_id)
        if config is None:
            raise JiraConfigurationError("Jira is not configured for this organization")

        client = jira_client or get_jira_client(finding.organization_id)
        ticket_key = finding.jira_ticket
        if ticket_key in (None, "", "NA", "None"):
            ticket_key = None
        issue_description = description or _finding_description(
            finding, scan_id or finding.scan_id
        )

        if ticket_key:
            try:
                client.add_comment(
                    ticket_key,
                    "Finding detected again by ArcherySec.\n\n%s" % issue_description,
                )
                return {"status": "updated", "jira_ticket": ticket_key}
            except JIRAError as error:
                if getattr(error, "status_code", None) != 404:
                    raise
                logger.warning(
                    "Stored Jira ticket %s is unavailable; creating a replacement "
                    "for finding id=%s",
                    ticket_key,
                    getattr(finding, "vuln_id", None),
                )
                finding.jira_ticket = None
                finding.save(update_fields=["jira_ticket", "updated_time"])

        destination_project = jira_project_id or _resolve_destination_project(
            client, config
        )
        if not destination_project:
            raise JiraConfigurationError(
                "Jira destination project ID is not configured"
            )

        selected_issue_type = _resolve_issue_type(
            client,
            destination_project,
            issue_type or config["issue_type"],
            config,
        )
        archery_project = getattr(finding, "project", None)
        project_label = getattr(archery_project, "project_name", "ArcherySec")
        issue_summary = summary or "[%s] %s" % (
            finding.severity or "Unspecified",
            finding.title or "Security finding",
        )
        issue_summary = "[%s] %s" % (project_label, issue_summary)
        new_issue = client.create_issue(
            fields={
                "project": {"id": destination_project},
                "summary": issue_summary,
                "description": issue_description,
                "issuetype": {"id": selected_issue_type},
            }
        )
        finding.jira_ticket = new_issue.key
        finding.save(update_fields=["jira_ticket", "updated_time"])
        return {"status": "created", "jira_ticket": new_issue.key}
    except Exception:
        logger.exception(
            "Jira processing failed for finding id=%s scanner=%s",
            getattr(finding, "vuln_id", None),
            getattr(finding, "scanner", None),
        )
        return {"status": "failed", "jira_ticket": finding.jira_ticket}


def process_scan_findings(project_id, scan_id, organization, scanner):
    """Push active findings from one committed scan without failing scan ingestion."""
    try:
        model, scanner_name = _scanner_result_model(scanner)
        config = get_jira_configuration(organization)
        if config is None:
            raise JiraConfigurationError("Jira is not configured for this organization")
        findings = model.objects.filter(
            project_id=project_id,
            scan_id=scan_id,
            organization_id=getattr(organization, "pk", organization),
            vuln_status="Open",
            false_positive="No",
            vuln_duplicate="No",
        )
        if scanner_name:
            findings = findings.filter(scanner__iexact=scanner_name)

        client = get_jira_client(organization)
        destination_project = _resolve_destination_project(client, config)
        return [
            process_finding(
                finding,
                jira_client=client,
                jira_project_id=destination_project,
                issue_type=config["issue_type"],
                scan_id=scan_id,
            )
            for finding in findings.iterator()
        ]
    except Exception:
        logger.exception(
            "Jira scan processing failed for scan_id=%s scanner=%s",
            scan_id,
            scanner,
        )
        return []


def find_scan_finding(finding_id, scan_id, scanner, organization):
    model, scanner_name = _scanner_result_model(scanner)
    findings = model.objects.filter(
        vuln_id=finding_id,
        scan_id=scan_id,
        organization_id=getattr(organization, "pk", organization),
    )
    if scanner_name:
        findings = findings.filter(scanner__iexact=scanner_name)
    return findings.order_by("-updated_time").first()


def enqueue_scan_findings(project_id, scan_id, organization, scanner):
    """Persist Jira work after a committed scan and schedule background tasks."""
    model, scanner_name = _scanner_result_model(scanner)
    findings = model.objects.filter(
        project_id=project_id,
        scan_id=scan_id,
        organization_id=getattr(organization, "pk", organization),
        vuln_status="Open",
        false_positive="No",
        vuln_duplicate="No",
    )
    if scanner_name:
        findings = findings.filter(scanner__iexact=scanner_name)

    organization_id = getattr(organization, "pk", organization)
    eligible_count = findings.count()
    created_count = 0
    for finding in findings.iterator():
        job, created = JiraSyncJob.objects.get_or_create(
            finding_id=finding.vuln_id,
            scan_id=scan_id,
            scanner=finding.scanner or scanner,
            organization_id=organization_id,
            defaults={"project_id": project_id},
        )
        if created:
            created_count += 1

    logger.info(
        "Enqueued Jira sync jobs: scanner=%s scan_id=%s eligible_findings=%d "
        "new_jobs=%d",
        scanner,
        scan_id,
        eligible_count,
        created_count,
    )


def find_finding(vuln_id, scanner, organization):
    model, scanner_name = _scanner_result_model(scanner)
    findings = model.objects.filter(
        vuln_id=vuln_id,
        organization_id=getattr(organization, "pk", organization),
    )
    if scanner_name:
        findings = findings.filter(scanner__iexact=scanner_name)
    return findings.order_by("-updated_time").first()


def link_finding_ticket(finding, jira_ticket_id, jira_client=None):
    """Link an existing Jira issue to a finding, or clear the stored link."""
    if not jira_ticket_id:
        finding.jira_ticket = None
        finding.save(update_fields=["jira_ticket", "updated_time"])
        return {"status": "unlinked", "jira_ticket": None}

    if finding.jira_ticket in (None, "", "NA", "None"):
        raise JiraConfigurationError("Finding has no current Jira ticket to link")

    client = jira_client or get_jira_client(finding.organization_id)
    return link_jira_issues(
        client,
        finding.jira_ticket,
        jira_ticket_id,
    )


def link_jira_issues(jira_client, current_ticket_id, linked_ticket_id):
    jira_client.create_issue_link(
        type="duplicates",
        inwardIssue=current_ticket_id,
        outwardIssue=linked_ticket_id,
    )
    return {"status": "linked", "jira_ticket": current_ticket_id}