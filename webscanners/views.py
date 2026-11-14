# -*- coding: utf-8 -*-
#                    _
#     /\            | |
#    /  \   _ __ ___| |__   ___ _ __ _   _
#   / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
#  / ____ \| | | (__| | | |  __/ |  | |_| |
# /_/    \_\_|  \___|_| |_|\___|_|   \__, |
#                                     __/ |
#                                    |___/
# Copyright (C) 2017 Anand Tiwari
#
# Email:   anandtiwarics@gmail.com
# Twitter: @anandtiwarics
#
# This file is part of ArcherySec Project.

from __future__ import unicode_literals

from urllib.parse import urlencode

from utility.finding_status import mark_finding

from django.contrib import messages
from django.http import HttpResponseRedirect
from django.shortcuts import HttpResponse, render
from django.urls import reverse
from notifications.models import Notification
from notifications.signals import notify
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from jiraticketing.models import jirasetting
from jiraticketing.services import get_jira_projects
from user_management import permissions
from webscanners.models import WebScanResultsDb, WebScansDb
from webscanners.scan_history import delete_scans, findings_for_scan
from webscanners.serializers import (WebScanResultsDbSerializer,
                                     WebScansDbSerializer)


class WebScanList(APIView):
    permission_classes = [IsAuthenticated | permissions.VerifyAPIKey]

    def get(self, request):
        all_scans = WebScansDb.objects.filter(organization=request.user.organization)
        all_notify = Notification.objects.unread()
        if request.path[:4] == "/api":
            serialized_data = WebScansDbSerializer(all_scans, many=True)
            return Response(serialized_data.data, status=status.HTTP_200_OK)
        else:
            return render(
                request,
                "webscanners/scans/list_scans.html",
                {"all_scans": all_scans, "message": all_notify},
            )


class WebScanVulnInfo(APIView):
    permission_classes = [IsAuthenticated | permissions.VerifyAPIKey]

    def get(self, request, uu_id=None):
        vuln_data = ""
        jira_url = None

        jira = jirasetting.objects.filter(organization=request.user.organization)
        for d in jira:
            jira_url = d.jira_server
        if uu_id is None:
            scan_id = request.GET["scan_id"]
            name = request.GET["scan_name"]
            vuln_data = findings_for_scan(scan_id, request.user.organization).filter(title=name)
        else:
            try:
                vuln_data = findings_for_scan(uu_id, request.user.organization)
            except Exception:
                return Response(
                    {"message": "Scan Id Doesn't Exist"},
                    status=status.HTTP_404_NOT_FOUND,
                )

        if request.path[:4] == "/api":
            serialized_data = WebScanResultsDbSerializer(vuln_data, many=True)
            return Response(serialized_data.data, status=status.HTTP_200_OK)
        else:
            return render(
                request,
                "webscanners/scans/list_vuln_info.html",
                {"vuln_data": vuln_data, "jira_url": jira_url},
            )


class WebScanVulnMark(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/scans/list_vuln_info.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        finding = mark_finding(request, WebScanResultsDb, WebScansDb)
        return HttpResponseRedirect(
            reverse("webscanners:list_vuln_info") + "?" + urlencode({
                "scan_id": str(request.data["scan_id"]), "scan_name": finding.title,
            })
        )


class WebScanDetails(APIView):
    enderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/scans/vuln_details.html"

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        jira_server = None
        jira_username = None
        jira_password = None
        jira_projects = None
        vuln_id = request.GET["vuln_id"]

        try:
            jira_projects = get_jira_projects(request.user.organization)
        except Exception:
            jira_projects = None

        vul_dat = WebScanResultsDb.objects.filter(
            vuln_id=vuln_id, organization=request.user.organization
        ).order_by("vuln_id")

        return render(
            request,
            "webscanners/scans/vuln_details.html",
            {"vul_dat": vul_dat, "jira_projects": jira_projects},
        )


class WebScanDelete(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/scans/list_scans.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        scan_id = request.POST.get("scan_id")

        delete_scans(str(scan_id).replace(" ", "").split(","), request.user.organization)
        return HttpResponseRedirect(reverse("webscanners:list_scans"))


class WebScanVulnDelete(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/scans/list_vuln_info.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        vuln_id = request.POST.get("vuln_id")
        scan_id = request.POST.get("scan_id")
        scan_item = str(vuln_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()
        for i in range(0, split_length):
            vuln_id = value_split.__getitem__(i)
            delete_vuln = WebScanResultsDb.objects.filter(
                vuln_id=vuln_id, organization=request.user.organization
            )
            delete_vuln.delete()
        all_vuln = WebScanResultsDb.objects.filter(
            scan_id=scan_id, organization=request.user.organization
        )

        total_vul = len(all_vuln)
        total_critical = len(all_vuln.filter(severity="Critical"))
        total_high = len(all_vuln.filter(severity="High"))
        total_medium = len(all_vuln.filter(severity="Medium"))
        total_low = len(all_vuln.filter(severity="Low"))
        total_info = len(all_vuln.filter(severity="Information"))

        WebScansDb.objects.filter(scan_id=scan_id).update(
            total_vul=total_vul,
            critical_vul=total_critical,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            info_vul=total_info,
            organization=request.user.organization,
        )
        return HttpResponseRedirect(
            reverse("webscanners:list_vuln") + "?scan_id=%s" % (scan_id)
        )


class WebScanVulnList(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/scans/list_vuln.html"

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        scan_id = request.GET["scan_id"]
        all_vuln = findings_for_scan(scan_id, request.user.organization)
        return render(
            request,
            "webscanners/scans/list_vuln.html",
            {
                "all_vuln": all_vuln,
                "scan_id": scan_id,
            },
        )
