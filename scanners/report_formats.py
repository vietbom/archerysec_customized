"""Validate native reports; retain legacy hashes and compute v2 finding identity.

Thesis changes TH-01..TH-04: docs/scanner-upgrade-2026-11-17.md.
"""
from dataclasses import dataclass
from collections import defaultdict
import json
import re
from urllib.parse import urljoin, urlsplit
from xml.etree import ElementTree

from rest_framework.exceptions import ValidationError

from scanners.vuln_checker import build_fingerprint
from scanners.finding_identity import evidence_hash, identity, normalized_path, normalized_url
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
    name = str(value or "UNKNOWN").strip().upper()
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
    identity_hash: str = ""
    identity_payload: dict = None
    identity_aliases: tuple = ()
    source_enriched: bool = False


def identified(legacy_payload, values, scanner, kind, **fields):
    stable_hash, payload = identity(scanner, kind, **fields)
    return Finding(build_fingerprint(legacy_payload), values,
                   identity_hash=stable_hash, identity_payload=payload)


def position(value, label):
    require(value is None or isinstance(value, dict), label + " must be an object.")
    value = value or {}
    for key in ("line", "col"):
        number = value.get(key)
        require(number is None or (type(number) is int and number >= 0), label + "." + key + " must be a non-negative integer.")
    return {"line": value.get("line"), "col": value.get("col")}


def source_line(value, label):
    require(value is None or (type(value) is int and value >= 0), label + " must be a non-negative integer.")
    return value


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
        require(native_id is None or isinstance(native_id, str), "Gitleaks Fingerprint must be a string.")
        source_line(line, "Gitleaks StartLine")
        fingerprint_data = {"scanner": "gitleaks", "report_fingerprint": native_id} if native_id else {
            "scanner": "gitleaks", "rule": rule, "file": path, "start_line": line,
            "commit": item.get("Commit") or item.get("commit")}
        details = {"Rule": rule, "Description": item.get("Description"), "Match": item.get("Match") or item.get("offender"),
                   "Commit": item.get("Commit") or item.get("commit"),
                   "Repository": item.get("Repo") or item.get("repo"),
                   "Message": item.get("Message") or item.get("commitMessage"),
                   "Author": item.get("Author") or item.get("author"),
                   "Email": item.get("Email") or item.get("email"),
                   "Date": item.get("Date") or item.get("date"), "Tags": item.get("Tags") or item.get("tags")}
        findings.append(identified(fingerprint_data, {
            "title": "%s in %s:%s" % (rule, path, line if line is not None else "unknown"),
            "fileName": path, "description": "\n".join("%s: %s" % (key, value if value is not None else "Not Found") for key, value in details.items()),
            "severity": "High", "severity_color": "danger",
            "references": serialize_references(*(item.get(key) for key in ("References", "references", "Reference", "reference", "Link", "link"))),
        }, "gitleaks", "secret", rule=rule, path=normalized_path(path), start_line=line,
            evidence=evidence_hash(item.get("Secret") or item.get("Match") or item.get("offender"))))
    return findings


def semgrep_import_warnings(data):
    """Only recoverable partial-parser warnings may accompany imported results."""
    errors = data.get("errors", [])
    require(errors is None or isinstance(errors, list), "Semgrep errors must be an array.")
    warnings = []
    for error in rows(errors, "Semgrep errors"):
        kind = error.get("type")
        kind = kind[0] if isinstance(kind, list) and kind else kind
        require(kind == "PartialParsing" and str(error.get("level", "")).lower() in ("warn", "warning"),
                "Semgrep reports scan errors; upload a complete successful scan before auto-closing findings.")
        message, path = error.get("message", "Partial parsing"), error.get("path", "")
        require(isinstance(message, str) and isinstance(path, str), "Semgrep warning path/message must be strings.")
        warnings.append({"type": "PartialParsing", "level": "warn", "path": path, "message": message})
    return warnings


def semgrep_source_identities(results):
    """CI-supplied hashes contain no source code; repeated matches stay distinct."""
    sources, matches, contexts = {}, defaultdict(set), defaultdict(set)
    for item in rows(results, "Semgrep results"):
        extra = item.get("extra") or {}
        if not isinstance(extra, dict) or extra.get("is_ignored") is True:
            continue
        source = extra.get("archerysec")
        if source is None:
            continue
        require(isinstance(source, dict) and source.get("version") == 1,
                "Semgrep ArcherySec source identity must use version 1.")
        require(isinstance(item.get("check_id"), str) and bool(item["check_id"])
                and isinstance(item.get("path"), str) and bool(item["path"]),
                "Each Semgrep finding needs check_id and path.")
        path, digest, context = (source.get(key) for key in ("relative_path", "match_sha256", "context_sha256"))
        require(isinstance(path, str) and bool(path) and not path.startswith(("/", "\\")) and ":" not in path
                and ".." not in path.replace("\\", "/").split("/"), "Semgrep source path must be repository-relative.")
        path = normalized_path(path)
        report_path = normalized_path(item.get("path") or "")
        require(report_path == path or report_path.endswith("/" + path), "Semgrep source path does not match the report path.")
        require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
                "Semgrep source match hash must be SHA-256.")
        require(context is None or (isinstance(context, str) and re.fullmatch(r"[0-9a-f]{64}", context) is not None),
                "Semgrep source context hash must be SHA-256.")
        key = (item.get("check_id"), path, digest)
        location = json.dumps([item.get("start"), item.get("end")], sort_keys=True)
        matches[key].add(location)
        contexts[key + (context,)].add(location)
        sources[id(item)] = (path, digest, context, key)
    return sources, matches, contexts


def semgrep_report(data):
    require(isinstance(data, dict) and isinstance(data.get("results"), list), "Semgrep JSON must contain a results array.")
    semgrep_import_warnings(data)
    sources, matches, contexts = semgrep_source_identities(data["results"])
    findings = []
    for item in rows(data["results"], "Semgrep results"):
        rule, path = item.get("check_id"), item.get("path")
        require(isinstance(rule, str) and bool(rule) and isinstance(path, str) and bool(path), "Each Semgrep finding needs check_id and path.")
        extra = item.get("extra")
        require(extra is None or isinstance(extra, dict), "Semgrep extra must be an object.")
        extra = extra or {}
        if extra.get("is_ignored") is True:
            continue
        native_ids = (extra.get("fingerprint"), extra.get("match_based_id"), item.get("match_based_id"))
        require(all(value is None or isinstance(value, str) for value in native_ids), "Semgrep fingerprint must be a string.")
        native_id = next((value.strip() for value in native_ids if value and value.strip()
                          and value.strip().lower() not in ("requires login", "not found", "...")), "")
        start = position(item.get("start"), "Semgrep start")
        finish = position(item.get("end"), "Semgrep end")
        location = start if start["line"] is not None else finish
        require(bool(native_id) or location["line"] is not None,
                "Semgrep needs a native fingerprint or start/end line for unambiguous identity.")
        legacy_fields = {"rule": rule, "path": normalized_path(path)}
        legacy_fields.update({"native_id": native_id} if native_id else {"position": location})
        stable_fields = dict(legacy_fields)
        source = sources.get(id(item))
        if source:
            relative_path, digest, context, key = source
            stable_fields["path"] = relative_path
            if not native_id and len(matches[key]) == 1:
                stable_fields.pop("position", None)
                stable_fields["source_match"] = digest
            elif not native_id and context and len(contexts[key + (context,)]) == 1:
                stable_fields.pop("position", None)
                stable_fields.update(source_match=digest, source_context=context)
        metadata = extra.get("metadata", "Not Found")
        reference_metadata = metadata if isinstance(metadata, dict) else {}
        risk, color = severity(extra.get("severity"))
        message, end, lines = extra.get("message", "Not Found"), item.get("end", "Not Found"), extra.get("lines", "Not Found")
        # Fingerprinting keeps the submitted implementation's severity mapping;
        # INFO can still be displayed separately as Informational.
        fingerprint_risk = {"ERROR": "High", "WARNING": "Medium"}.get(extra.get("severity"), "Low")
        fingerprint_data = {"scanner": "Semgrep", "check_id": rule, "severity": fingerprint_risk,
                  "path": path, "message": message, "metadata": metadata, "end": end, "lines": lines}
        findings.append(identified(fingerprint_data, {
            "title": rule, "fileName": path, "severity": risk, "severity_color": color,
            "description": "\n\n".join(str(value) for value in (message, rule, end, extra.get("metavars", "Not Found"), metadata, lines)),
            "solution": str(extra.get("fix") or ""),
            "references": serialize_references(reference_metadata.get("references"), reference_metadata.get("source"),
                reference_metadata.get("source-rule-url"), reference_metadata.get("shortlink"), extra.get("references")),
        }, "Semgrep", "sast", **stable_fields))
        aliases = []
        if native_id:
            aliases.append(identity("Semgrep", "sast", rule=rule, path=normalized_path(path), position=location)[0])
        if source:
            # Adopt exact prior evidence/position; never guess by rule/file.
            aliases.append(identity("Semgrep", "sast", **legacy_fields)[0])
            source_fields = {"rule": rule, "path": relative_path, "source_match": digest}
            if len(matches[key]) == 1:
                aliases.append(identity("Semgrep", "sast", **source_fields)[0])
            if context and len(contexts[key + (context,)]) == 1:
                aliases.append(identity("Semgrep", "sast", **source_fields, source_context=context)[0])
        findings[-1].identity_aliases = tuple(set(aliases) - {findings[-1].identity_hash})
        findings[-1].source_enriched = bool(source)
    return findings


def trivy_report(data):
    require(isinstance(data, dict) and data.get("ArtifactType") in ("container_image", "filesystem", "repository", "rootfs"),
            "Trivy requires a native JSON report with a supported ArtifactType.")
    require("Results" in data or data.get("SchemaVersion") in (1, 2), "Trivy JSON is missing Results and SchemaVersion.")
    require(not data.get("Errors") and not data.get("Error"), "Trivy reports execution errors; refusing reconciliation.")
    findings = []
    for result in rows(data.get("Results"), "Trivy Results"):
        target = result.get("Target")
        require(isinstance(target, str) and bool(target), "Each Trivy result needs Target.")
        target_class, target_type = result.get("Class", ""), result.get("Type", "")
        for item in rows(result.get("Vulnerabilities"), "Trivy Vulnerabilities"):
            vuln_id, package = item.get("VulnerabilityID"), item.get("PkgName")
            require(isinstance(vuln_id, str) and bool(vuln_id) and isinstance(package, str) and bool(package),
                    "Each Trivy vulnerability needs VulnerabilityID and PkgName strings.")
            package_path = item.get("PkgPath") or ""
            require(isinstance(package_path, str), "Trivy PkgPath must be a string.")
            require(item.get("InstalledVersion") is None or isinstance(item["InstalledVersion"], str),
                    "Trivy InstalledVersion must be a string.")
            installed, fixed = item.get("InstalledVersion", "Not Found"), item.get("FixedVersion", "Not Found")
            title = item.get("Title", "Not Found")
            risk, color = severity(item.get("Severity"))
            fingerprint_data = {"scanner": "Trivy", "artifact_type": data.get("ArtifactType"), "vulnerability_id": vuln_id,
                "package": package, "installed_version": installed, "fixed_version": fixed, "title": title,
                "severity": risk, "target": target, "type": target_type, "class": target_class}
            stable_target = "os-root" if data.get("ArtifactType") == "container_image" and target_class == "os-pkgs" else normalized_path(target)
            findings.append(identified(fingerprint_data, {
                "title": vuln_id, "fileName": package, "filePath": package_path or target, "severity": risk, "severity_color": color,
                "description": "\n\n".join(str(value) for value in (item.get("Description", "Not Found"), title, target, target_type,
                    target_class, vuln_id, package, installed, fixed, "Package path: " + (package_path or target))),
                "solution": "%s can be fixed by upgrading version: %s" % (package, fixed),
                "references": serialize_references(item.get("References"), item.get("PrimaryURL")),
            }, "Trivy", "vulnerability", artifact_type=data.get("ArtifactType"), target=stable_target,
                target_class=target_class, target_type=target_type, vulnerability_id=vuln_id,
                package=package, package_path=normalized_path(package_path), installed_version=item.get("InstalledVersion") or ""))
        for item in rows(result.get("Secrets"), "Trivy Secrets"):
            title = item.get("Title")
            rule = item.get("RuleID") or title
            require(bool(rule), "Each Trivy secret needs RuleID or Title.")
            start, end = item.get("StartLine"), item.get("EndLine")
            source_line(start, "Trivy secret StartLine")
            source_line(end, "Trivy secret EndLine")
            match, category = item.get("Match", ""), item.get("Category", "")
            risk, color = severity(item.get("Severity"))
            fingerprint_data = {"scanner": "Trivy", "artifact_type": data.get("ArtifactType"), "type": "secret", "title": title,
                "severity": risk, "target": target, "match": match, "category": category, "start_line": start, "end_line": end}
            findings.append(identified(fingerprint_data, {
                    "title": title or rule, "fileName": target, "severity": risk, "severity_color": color,
                    "description": "%s\n\n%s\n\nStart Line: %s\nEnd Line: %s\n%s" % (title, match, start, end, category),
                    "solution": "Remove the secret from the code and rotate the affected credential.",
                    "references": serialize_references(item.get("References"), item.get("PrimaryURL"))},
                "Trivy", "secret", artifact_type=data.get("ArtifactType"), rule=rule,
                target=normalized_path(target), start_line=start, evidence=evidence_hash(match)))
        for item in rows(result.get("Misconfigurations"), "Trivy Misconfigurations"):
            if item.get("Status", "FAIL") in ("PASS", "EXCEPTION"):
                continue
            title, rule = item.get("Title"), item.get("ID") or item.get("AVDID") or item.get("Title")
            require(bool(rule), "Each Trivy misconfiguration needs ID, AVDID or Title.")
            cause = item.get("CauseMetadata")
            require(cause is None or isinstance(cause, dict), "Trivy CauseMetadata must be an object.")
            cause = cause or {}
            start, end = cause.get("StartLine"), cause.get("EndLine")
            source_line(start, "Trivy config StartLine")
            source_line(end, "Trivy config EndLine")
            message, resolution = item.get("Message", ""), item.get("Resolution", "")
            resource, provider, code = cause.get("Resource", ""), cause.get("Provider", ""), cause.get("Code", [])
            risk, color = severity(item.get("Severity"))
            fingerprint_data = {"scanner": "Trivy", "artifact_type": data.get("ArtifactType"), "type": "config", "title": title,
                "severity": risk, "target": target, "message": message, "resolution": resolution, "resource": resource,
                "provider": provider, "code": code, "start_line": start, "end_line": end}
            findings.append(identified(fingerprint_data, {
                "title": title or rule, "fileName": target, "severity": risk, "severity_color": color,
                "description": "\n\n".join(str(value) for value in (item.get("Description", ""), title, message,
                    "Start Line: %s" % start, "End Line: %s" % end, resource, provider, code)),
                "solution": resolution, "references": serialize_references(item.get("References"), item.get("PrimaryURL")),
            }, "Trivy", "configuration", artifact_type=data.get("ArtifactType"), rule=rule,
                target=normalized_path(target), resource=resource, provider=provider, start_line=start))
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
    # ZAP reports also contain insights/insight/site and stoppingInsight/site
    # text fields. Only direct report children describe targets with alerts.
    sites = root.findall("site")
    require(bool(sites) and all(site.get("name") for site in sites), "ZAP report must contain named sites, including sites with no alerts.")
    findings = []
    for site in sites:
        alerts = site.find("alerts")
        require(alerts is not None, "ZAP site is missing its alerts element.")
        url = site.get("name")
        try:
            parsed_url = urlsplit(url)
            require(parsed_url.scheme in ("http", "https") and bool(parsed_url.hostname), "ZAP site name must be an HTTP(S) URL.")
            require(not any(character.isspace() for character in url), "ZAP site URL must not contain whitespace.")
            site_identity = normalized_url(url)
        except ValueError as error:
            raise ReportValidationError("ZAP site URL is invalid.") from error
        for item in alerts.findall("alertitem"):
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
            values = {
                "url": url, "title": title, "solution": xml_value(item.find("solution")), "description": description,
                "reference": serialize_references(reference if reference != "NA" else None),
                "instance": json.dumps(instances, ensure_ascii=False), "severity": risk, "severity_color": color,
            }
            # TH-03: one finding per rule/site/endpoint/method/parameter. Changes
            # to evidence or instance order do not transfer FP to other URLs.
            for instance in instances or [None]:
                endpoint = None
                if instance is not None:
                    uri = instance.get("uri") or instance.get("url")
                    uri = urljoin(url + "/", uri) if uri and uri != "NA" else url
                    try:
                        parsed = urlsplit(uri)
                        require(parsed.scheme in ("http", "https") and bool(parsed.hostname), "ZAP instance URI must be an HTTP(S) URL.")
                        require(not any(character.isspace() for character in uri), "ZAP instance URI must not contain whitespace.")
                        endpoint = {"uri": normalized_url(uri), "method": (instance.get("method") or "GET").upper(),
                                    "param": "" if instance.get("param") in (None, "NA") else instance["param"]}
                    except ValueError as error:
                        raise ReportValidationError("ZAP instance URI is invalid.") from error
                single_values = dict(values, instance=json.dumps([instance] if instance else [], ensure_ascii=False))
                findings.append(identified(fingerprint_data, single_values, "Zap", "dast", site=site_identity,
                    rule=rule, endpoint=endpoint))
    grouped = {}
    for finding in findings:
        existing = grouped.get(finding.identity_hash)
        if existing is None:
            grouped[finding.identity_hash] = finding
            continue
        instances = json.loads(existing.values["instance"])
        for instance in json.loads(finding.values["instance"]):
            if instance not in instances:
                instances.append(instance)
        existing.values["instance"] = json.dumps(instances, ensure_ascii=False)
    return list(grouped.values()), sites[0].get("name")
