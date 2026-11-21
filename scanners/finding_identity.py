"""Versioned identity policy. See docs/scanner-upgrade-2026-11-17.md (TH-01)."""
import hashlib
import posixpath
from urllib.parse import urlsplit, urlunsplit

from scanners.vuln_checker import build_fingerprint


IDENTITY_VERSION = 2


def identity(scanner, kind, **fields):
    payload = {"identity_version": IDENTITY_VERSION, "scanner": scanner, "kind": kind, **fields}
    return build_fingerprint(payload), payload


def normalized_path(value):
    return posixpath.normpath(value.replace("\\", "/")) if value else ""


def evidence_hash(value):
    # Do not put the clear-text secret in the identity payload.
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest() if value else ""


def normalized_url(value):
    parsed = urlsplit(value)
    hostname = parsed.hostname or ""
    host = "[" + hostname.lower() + "]" if ":" in hostname else hostname.lower()
    port = parsed.port
    if port and (parsed.scheme.lower(), port) not in (("http", 80), ("https", 443)):
        host += ":" + str(port)
    return urlunsplit((parsed.scheme.lower(), host, parsed.path or "/", parsed.query, ""))
