"""Validate native reports while retaining the original scanner fingerprints."""
from dataclasses import dataclass
import hashlib
import json
import re
from urllib.parse import urlsplit
from xml.etree import ElementTree

from rest_framework.exceptions import ValidationError

from scanners.vuln_checker import build_fingerprint
from utility.references import serialize_references


class ReportValidationError(ValidationError):
    pass


def require(condition, message):
    if not condition:
        raise ReportValidationError(message)


def rows(value, label):
    if value is None:
        return []
    require(isinstance(value, list) and all(isinstance(item, dict) for item in value),
            label + " must be an array of objects.")
    return value


def severity(value):
    name = str(value or "UNKNOWN").upper()
    name = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "INFORMATIONAL",
            "INFORMATION": "INFORMATIONAL", "UNKNOWN": "LOW"}.get(name, name)
    return {"CRITICAL": ("Critical", "critical"), "HIGH": ("High", "danger"),
            "MEDIUM": ("Medium", "warning"), "LOW": ("Low", "info"),
            "INFORMATIONAL": ("Informational", "info")}.get(name, ("Low", "info"))


@dataclass
class Finding:
    duplicate_hash: str
    values: dict
    suppression_hash: str = ""


def gitleaks_report(data):
    require(data is None or isinstance(data, list), "Gitleaks requires a native JSON array (or null for no findings).")
    findings = []
    for item in rows(data, "Gitleaks findings"):
        rule = item.get("RuleID") or item.get("rule") or item.get("Rule")
        path = item.get("File") or item.get("file")
        require(isinstance(rule, str) and bool(rule) and isinstance(path, str) and bool(path),
                "Each Gitleaks finding needs RuleID and File.")
        line = item.get("StartLine") or item.get("line")
        native_id = item.get("Fingerprint")
        fingerprint_data = {"scanner": "gitleaks", "report_fingerprint": native_id} if native_id else {
            "scanner": "gitleaks", "rule": rule, "file": path, "start_line": line,
            "commit": item.get("Commit") or item.get("commit")}
        details = {"Rule": rule, "Match": item.get("Match") or item.get("offender"),
                   "Commit": item.get("Commit") or item.get("commit"),
                   "Repository": item.get("Repo") or item.get("repo"),
                   "Message": item.get("Message") or item.get("commitMessage"),
                   "Author": item.get("Author") or item.get("author"),
                   "Email": item.get("Email") or item.get("email"),
                   "Date": item.get("Date") or item.get("date"), "Tags": item.get("Tags") or item.get("tags")}
        findings.append(Finding(build_fingerprint(fingerprint_data), {
            "title": "%s in %s:%s" % (rule, path, line if line is not None else "unknown"),
            "fileName": path, "description": "\n".join("%s: %s" % (key, value if value is not None else "Not Found") for key, value in details.items()),
            "severity": "High", "severity_color": "danger",
            "references": serialize_references(*(item.get(key) for key in ("References", "references", "Reference", "reference", "Link", "link"))),
        }))
    return findings


def semgrep_report(data):
    require(isinstance(data, dict) and isinstance(data.get("results"), list), "Semgrep JSON must contain a results array.")
    require(not data.get("errors"), "Semgrep reports scan errors; upload a complete successful scan before auto-closing findings.")
    findings = []
    for item in rows(data["results"], "Semgrep results"):
        rule, path = item.get("check_id"), item.get("path")
        require(isinstance(rule, str) and bool(rule) and isinstance(path, str) and bool(path), "Each Semgrep finding needs check_id and path.")
        extra = item.get("extra") or {}
        require(isinstance(extra, dict), "Semgrep extra must be an object.")
        if extra.get("is_ignored") is True:
            continue
        metadata = extra.get("metadata", "Not Found")
        reference_metadata = metadata if isinstance(metadata, dict) else {}
        risk, color = severity(extra.get("severity"))
        message, end, lines = extra.get("message", "Not Found"), item.get("end", "Not Found"), extra.get("lines", "Not Found")
        # Fingerprinting keeps the submitted implementation's severity mapping;
        # INFO can still be displayed separately as Informational.
        fingerprint_risk = {"ERROR": "High", "WARNING": "Medium"}.get(extra.get("severity"), "Low")
        fingerprint_data = {"scanner": "Semgrep", "check_id": rule, "severity": fingerprint_risk,
                  "path": path, "message": message, "metadata": metadata, "end": end, "lines": lines}
        findings.append(Finding(build_fingerprint(fingerprint_data), {
            "title": rule, "fileName": path, "severity": risk, "severity_color": color,
            "description": "\n\n".join(str(value) for value in (message, rule, end, extra.get("metavars", "Not Found"), metadata, lines)),
            "solution": str(extra.get("fix") or ""),
            "references": serialize_references(reference_metadata.get("references"), reference_metadata.get("source"),
                reference_metadata.get("source-rule-url"), reference_metadata.get("shortlink"), extra.get("references")),
        }))
    return findings


def trivy_report(data):
    require(isinstance(data, dict) and data.get("ArtifactType") in ("container_image", "filesystem", "repository", "rootfs"),
            "Trivy requires a native JSON report with a supported ArtifactType.")
    require("Results" in data or data.get("SchemaVersion") in (1, 2), "Trivy JSON is missing Results and SchemaVersion.")
    findings = []
    for result in rows(data.get("Results"), "Trivy Results"):
        target = result.get("Target")
        require(isinstance(target, str) and bool(target), "Each Trivy result needs Target.")
        target_class, target_type = result.get("Class", ""), result.get("Type", "")
        for item in rows(result.get("Vulnerabilities"), "Trivy Vulnerabilities"):
            vuln_id, package = item.get("VulnerabilityID"), item.get("PkgName")
            require(bool(vuln_id) and bool(package), "Each Trivy vulnerability needs VulnerabilityID and PkgName.")
            installed, fixed = item.get("InstalledVersion", "Not Found"), item.get("FixedVersion", "Not Found")
            title = item.get("Title", "Not Found")
            risk, color = severity(item.get("Severity"))
            fingerprint_data = {"scanner": "Trivy", "artifact_type": data.get("ArtifactType"), "vulnerability_id": vuln_id,
                "package": package, "installed_version": installed, "fixed_version": fixed, "title": title,
                "severity": risk, "target": target, "type": target_type, "class": target_class}
            findings.append(Finding(build_fingerprint(fingerprint_data), {
                "title": vuln_id, "fileName": package, "filePath": target, "severity": risk, "severity_color": color,
                "description": "\n\n".join(str(value) for value in (item.get("Description", "Not Found"), title, target, target_type,
                    target_class, vuln_id, package, installed, fixed)),
                "solution": "%s can be fixed by upgrading version: %s" % (package, fixed),
                "references": serialize_references(item.get("References"), item.get("PrimaryURL")),
            }))
        for item in rows(result.get("Secrets"), "Trivy Secrets"):
            title = item.get("Title")
            rule = item.get("RuleID") or title
            require(bool(rule), "Each Trivy secret needs RuleID or Title.")
            start, end = item.get("StartLine"), item.get("EndLine")
            match, category = item.get("Match", ""), item.get("Category", "")
            risk, color = severity(item.get("Severity"))
            fingerprint_data = {"scanner": "Trivy", "artifact_type": data.get("ArtifactType"), "type": "secret", "title": title,
                "severity": risk, "target": target, "match": match, "category": category, "start_line": start, "end_line": end}
            findings.append(Finding(build_fingerprint(fingerprint_data), {
                    "title": title or rule, "fileName": target, "severity": risk, "severity_color": color,
                    "description": "%s\n\n%s\n\nStart Line: %s\nEnd Line: %s\n%s" % (title, match, start, end, category),
                    "solution": "Remove the secret from the code and rotate the affected credential.",
                    "references": serialize_references(item.get("References"), item.get("PrimaryURL"))}))
        for item in rows(result.get("Misconfigurations"), "Trivy Misconfigurations"):
            if item.get("Status", "FAIL") in ("PASS", "EXCEPTION"):
                continue
            title, rule = item.get("Title"), item.get("ID") or item.get("AVDID") or item.get("Title")
            require(bool(rule), "Each Trivy misconfiguration needs ID, AVDID or Title.")
            cause = item.get("CauseMetadata") or {}
            require(isinstance(cause, dict), "Trivy CauseMetadata must be an object.")
            start, end = cause.get("StartLine"), cause.get("EndLine")
            message, resolution = item.get("Message", ""), item.get("Resolution", "")
            resource, provider, code = cause.get("Resource", ""), cause.get("Provider", ""), cause.get("Code", [])
            risk, color = severity(item.get("Severity"))
            fingerprint_data = {"scanner": "Trivy", "artifact_type": data.get("ArtifactType"), "type": "config", "title": title,
                "severity": risk, "target": target, "message": message, "resolution": resolution, "resource": resource,
                "provider": provider, "code": code, "start_line": start, "end_line": end}
            findings.append(Finding(build_fingerprint(fingerprint_data), {
                "title": title or rule, "fileName": target, "severity": risk, "severity_color": color,
                "description": "\n\n".join(str(value) for value in (item.get("Description", ""), title, message,
                    "Start Line: %s" % start, "End Line: %s" % end, resource, provider, code)),
                "solution": resolution, "references": serialize_references(item.get("References"), item.get("PrimaryURL")),
            }))
    return findings


def xml_value(element, default="NA"):
    if element is None:
        return default
    return (element.text or "") + "".join(ElementTree.tostring(child, encoding="unicode", method="html") for child in element) or default


def xml_fingerprint_value(element):
    """Original ZAP hashing used element.text, before formatting nested HTML."""
    return (element.text or "NA") if element is not None else "NA"


def zap_report(root):
    require(root.tag == "OWASPZAPReport", "ZAP requires an OWASPZAPReport XML report.")
    sites = list(root.iter("site"))
    require(bool(sites) and all(site.get("name") for site in sites), "ZAP report must contain named sites, including sites with no alerts.")
    findings = []
    for site in sites:
        require(site.find("alerts") is not None, "ZAP site is missing its alerts element.")
        url = site.get("name")
        parsed_url = urlsplit(url)
        require(parsed_url.scheme in ("http", "https") and bool(parsed_url.netloc), "ZAP site name must be an HTTP(S) URL.")
        for item in site.iter("alertitem"):
            alert = xml_value(item.find("alert"))
            title = xml_value(item.find("name"), alert)
            rule = xml_value(item.find("alertRef"), "") or xml_value(item.find("pluginid"), "") or alert or title
            require(title != "NA" and bool(rule), "ZAP alert requires an alert name or plugin ID.")
            riskcode = xml_value(item.find("riskcode"))
            require(riskcode in ("0", "1", "2", "3", "4"), "ZAP alert has an invalid riskcode.")
            risk, color = {"4": ("Critical", "critical"), "3": ("High", "danger"), "2": ("Medium", "warning"),
                           "1": ("Low", "info"), "0": ("Informational", "info")}[riskcode]
            description, reference = xml_value(item.find("desc")), xml_value(item.find("reference"))
            instances = [{child.tag: child.text or "NA" for child in instance} for instance in item.findall("instances/instance")]
            fingerprint_instances = []
            for instance in item.findall("instances/instance"):
                values = {}
                for child in instance:
                    value = re.sub(r"<[^>]*>", " ", str(child.text))
                    values[child.tag] = "NA" if value == "None" else value
                fingerprint_instances.append(values)
            # Keep the original fields/values, independently of displayed severity
            # and reference-link normalization (including CDATA/nested HTML).
            fingerprint_data = {"scanner": "Zap", "title": xml_fingerprint_value(item.find("name")),
                "severity": "Low" if riskcode == "0" else risk, "scan_url": url,
                "alert": xml_fingerprint_value(item.find("alert")), "instance": fingerprint_instances,
                "description": xml_fingerprint_value(item.find("desc")),
                "reference": xml_fingerprint_value(item.find("reference"))}
            findings.append(Finding(build_fingerprint(fingerprint_data), {
                "url": url, "title": title, "solution": xml_value(item.find("solution")), "description": description,
                "reference": serialize_references(reference if reference != "NA" else None),
                "instance": json.dumps(instances, ensure_ascii=False), "severity": risk, "severity_color": color,
            }, hashlib.sha256((str(title) + str(url) + str(risk)).encode("utf-8")).hexdigest()))
    return findings, sites[0].get("name")
