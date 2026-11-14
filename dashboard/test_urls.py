"""Real dashboard/triage endpoints with placeholders for unrelated navigation."""
import re
from collections import defaultdict
from pathlib import Path

from django.conf import settings
from django.http import HttpResponse
from django.urls import include, path

from common.notification_views import dismiss_all_notifications, dismiss_notification
from scanners.scanner_parser import scanner_parser  # registers template filters
from staticscanners.views import (SastScanDetails, SastScanVulnInfo, SastScanVulnMark,
                                 SastScanVulnList, SastScanList, SastScanDelete)
from webscanners.views import (WebScanDelete, WebScanDetails, WebScanList,
                              WebScanVulnInfo, WebScanVulnList, WebScanVulnMark)
from report_upload.views import Upload
from archeryapi.views import UploadScanResult


def placeholder(request):
    return HttpResponse("Navigation target outside this regression suite")


names = defaultdict(set)
for template in (Path(settings.BASE_DIR) / "templates").rglob("*.html"):
    for name in re.findall(r"{%\s*url\s+['\"]([^'\"]+)", template.read_text(encoding="utf-8")):
        if ":" in name:
            namespace, local = name.split(":", 1)
            names[namespace].add(local)

real = {
    "staticscanners": {"vuln_mark": SastScanVulnMark.as_view(),
                       "list_vuln": SastScanVulnList.as_view(),
                       "list_scans": SastScanList.as_view(),
                       "scan_delete": SastScanDelete.as_view(),
                       "scan_details": SastScanDetails.as_view(),
                       "list_vuln_info": SastScanVulnInfo.as_view()},
    "webscanners": {"vuln_mark": WebScanVulnMark.as_view(),
                    "list_scans": WebScanList.as_view(),
                    "list_vuln": WebScanVulnList.as_view(),
                    "scan_delete": WebScanDelete.as_view(),
                    "scan_details": WebScanDetails.as_view(),
                    "list_vuln_info": WebScanVulnInfo.as_view(),
                    "del_notify": dismiss_notification,
                    "del_all_notify": dismiss_all_notifications},
    "report_upload": {"upload": Upload.as_view()},
}
urlpatterns = [path("dashboard/", include("dashboard.urls")),
               path("api/v1/uploadscan/", UploadScanResult.as_view(), name="test_api_upload"),
               path("logout/", placeholder, name="logout")]
for namespace, links in names.items():
    if namespace == "dashboard":
        continue
    routes = [path(name + "/", real.get(namespace, {}).get(name, placeholder), name=name)
              for name in links | set(real.get(namespace, {}))]
    urlpatterns.append(path(namespace + "/", include((routes, namespace))))
