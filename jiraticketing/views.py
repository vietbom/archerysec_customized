import logging
import uuid

from django.contrib import messages
from django.core import signing
from django.shortcuts import HttpResponseRedirect, render
from django.urls import reverse
from notifications.signals import notify
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.views import APIView

from archerysettings.models import SettingsDb
from jiraticketing.models import jirasetting
from jiraticketing.services import (
    find_finding,
    get_jira_configuration,
    get_jira_projects,
    link_finding_ticket,
    process_finding,
    validate_jira_connection,
)
from user_management import permissions

logger = logging.getLogger(__name__)


def _finding_redirect(scanner, scan_id, summary, finding=None):
    if scanner == "web":
        return HttpResponseRedirect(
            reverse("webscanners:list_vuln_info")
            + "?scan_id=%s&scan_name=%s" % (scan_id, summary)
        )
    if scanner in ("sast", "gitleaks", "semgrep", "semgrepscan", "trivy"):
        return HttpResponseRedirect(
            reverse("staticscanners:list_vuln_info")
            + "?scan_id=%s&test_name=%s" % (scan_id, summary)
        )
    if scanner == "network":
        return HttpResponseRedirect(
            reverse("networkscanners:list_vuln_info")
            + "?scan_id=%s&ip=%s" % (scan_id, getattr(finding, "ip", ""))
        )
    if scanner == "cloud":
        return HttpResponseRedirect(
            reverse("cloudscanners:list_vuln_info")
            + "?scan_id=%s&scan_name=%s" % (scan_id, summary)
        )
    return HttpResponseRedirect(reverse("dashboard:dashboard"))


class JiraSetting(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/scans/list_scans.html"
    permission_classes = (IsAuthenticated, permissions.IsAdmin)

    def get(self, request):
        jira_projects = []
        try:
            config = get_jira_configuration(request.user.organization)
            if config:
                jira_projects = get_jira_projects(request.user.organization)
        except Exception:
            logger.exception("Stored Jira credentials could not be decoded")
            config = None
        return render(
            request,
            "jiraticketing/jira_setting_form.html",
            {
                "jira_server": config["server"] if config else "",
                "jira_username": config["username"] if config else "",
                "jira_password": config["password"] if config else "",
                "jira_project_id": config["project_id"] if config else "",
                "jira_projects": jira_projects,
            },
        )

    def post(self, request):
        organization = request.user.organization
        jira_url = request.POST.get("jira_url")
        jira_username = request.POST.get("jira_username") or ""
        jira_password = request.POST.get("jira_password") or ""
        jira_project_id = request.POST.get("jira_project_id") or ""

        try:
            projects = validate_jira_connection(
                jira_url, jira_username, jira_password
            )
            project_ids = {
                str(value)
                for project in projects
                for value in (
                    getattr(project, "id", None),
                    getattr(project, "key", None),
                )
                if value
            }
            if not jira_project_id and len(projects) == 1:
                jira_project_id = str(
                    getattr(projects[0], "id", None)
                    or getattr(projects[0], "key", "")
                )
            if not jira_project_id or jira_project_id not in project_ids:
                messages.error(
                    request,
                    "Select a Jira project that is accessible with these credentials.",
                )
                return render(
                    request,
                    "jiraticketing/jira_setting_form.html",
                    {
                        "jira_server": jira_url,
                        "jira_username": jira_username,
                        "jira_password": jira_password,
                        "jira_project_id": jira_project_id,
                        "jira_projects": projects,
                    },
                )
        except Exception:
            logger.exception("Jira connection validation failed")
            messages.error(request, "Unable to connect to Jira with these credentials")
            return HttpResponseRedirect(reverse("jiraticketing:jira_setting"))

        setting = jirasetting.objects.filter(organization=organization).order_by(
            "-created_time"
        ).first()
        setting_id = (
            setting.setting_id if setting and setting.setting_id else uuid.uuid4()
        )
        if setting is None:
            setting = jirasetting(setting_id=setting_id, organization=organization)

        setting.setting_id = setting_id
        setting.jira_server = jira_url
        setting.jira_username = signing.dumps(jira_username)
        setting.jira_password = signing.dumps(jira_password)
        setting.jira_project_id = jira_project_id
        setting.save()

        setting_info = SettingsDb(
            setting_id=setting_id,
            setting_scanner="Jira",
            organization=organization,
        )
        setting_info.setting_status = True
        logger.info("Jira connection validated; available projects=%d", len(projects))
        setting_info.save()

        return HttpResponseRedirect(reverse("archerysettings:settings"))


class CreateJiraTicket(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/scans/list_scans.html"
    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        jira_projects = []
        try:
            jira_projects = get_jira_projects(request.user.organization)
        except Exception:
            logger.exception("Unable to load Jira projects for ticket form")
            notify.send(
                request.user,
                recipient=request.user,
                verb="Jira settings not found",
            )

        summary = request.GET.get("summary", "")
        description = request.GET.get("description", "")
        scanner = request.GET.get("scanner", "")
        vuln_id = request.GET.get("vuln_id", "")
        scan_id = request.GET.get("scan_id", "")
        return render(
            request,
            "jiraticketing/submit_jira_ticket.html",
            {
                "jira_projects": jira_projects,
                "summary": summary,
                "description": description,
                "scanner": scanner,
                "vuln_id": vuln_id,
                "scan_id": scan_id,
            },
        )

    def post(self, request):
        summary = request.POST.get("summary", "")
        scanner = request.POST.get("scanner", "")
        vuln_id = request.POST.get("vuln_id")
        scan_id = request.POST.get("scan_id")
        finding = find_finding(vuln_id, scanner, request.user.organization)
        if finding is None:
            messages.error(request, "Finding not found")
            return _finding_redirect(scanner, scan_id, summary)

        result = process_finding(
            finding,
            jira_project_id=request.POST.get("project_id"),
            issue_type=request.POST.get("issue_type"),
            summary=summary,
            description=request.POST.get("description", ""),
        )
        if result["status"] == "failed":
            messages.error(request, "Unable to create or update the Jira ticket")
        else:
            messages.success(
                request,
                "Jira ticket %s: %s" % (result["status"], result["jira_ticket"]),
            )
        return _finding_redirect(scanner, scan_id, summary, finding)


class LinkJiraTicket(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/scans/list_scans.html"
    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        scanner = request.GET.get("scanner", "")
        return render(
            request,
            "jiraticketing/link_jira_ticket.html",
            {
                "summary": request.GET.get("summary", ""),
                "jira_tick_id": request.GET.get("jira_tick_id", ""),
                "scanner": scanner,
                "vuln_id": request.GET.get("vuln_id", ""),
                "scan_id": request.GET.get("scan_id", ""),
            },
        )

    def post(self, request):
        summary = request.POST.get("summary", "")
        scanner = request.POST.get("scanner", "")
        vuln_id = request.POST.get("vuln_id")
        scan_id = request.POST.get("scan_id")
        finding = find_finding(vuln_id, scanner, request.user.organization)
        if finding is None:
            messages.error(request, "Finding not found")
            return _finding_redirect(scanner, scan_id, summary)

        try:
            result = link_finding_ticket(finding, request.POST.get("jira_tick_id"))
            messages.success(
                request,
                "Jira ticket link %s: %s" % (result["status"], result["jira_ticket"]),
            )
        except Exception:
            logger.exception("Unable to link Jira ticket for finding %s", vuln_id)
            messages.warning(request, "Jira ticket could not be linked")
        return _finding_redirect(scanner, scan_id, summary, finding)