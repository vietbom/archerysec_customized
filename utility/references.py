"""Read scanner references without changing legacy report data."""
import ast
import html
from html.parser import HTMLParser
import json
import re
from urllib.parse import urlsplit

from django.utils.html import strip_tags


URL_PATTERN = re.compile(r"https?://[^\s<>\"]+", re.IGNORECASE)
HTML_TAG_PATTERN = re.compile(r"</?(?:a|p|br|div|li|ul|ol|span)\b", re.IGNORECASE)


def _is_http_url(value):
    if any(character.isspace() or ord(character) < 32 for character in value):
        return False
    try:
        parsed = urlsplit(value)
        return parsed.scheme.lower() in ("http", "https") and bool(parsed.hostname)
    except ValueError:
        return False


class _ReferenceLinks(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.urls = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            for key, value in attrs:
                if key.lower() == "href" and value and _is_http_url(value):
                    self.urls.append(value)


def _items(value):
    if value is None:
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            yield from _items(item)
        return
    text = str(value).strip()
    if not text:
        return
    # TextField historically stores Trivy's Python list representation. Accept
    # JSON as well, while leaving plain URLs and descriptive text intact.
    if text.startswith(("[", "(")) and len(text) <= 262144:
        for parse in (json.loads, ast.literal_eval):
            try:
                decoded = parse(text)
            except (ValueError, SyntaxError, RecursionError):
                continue
            if isinstance(decoded, (list, tuple)):
                yield from _items(decoded)
                return
    if not HTML_TAG_PATTERN.search(text) and _is_http_url(text):
        yield {"url": text, "text": text}
        return

    parser = _ReferenceLinks()
    parser.feed(text)
    urls = list(parser.urls)
    # Break HTML paragraphs/line breaks into separate reference boundaries.
    plain_text = strip_tags(re.sub(r"<[^>]+>", " ", text))
    plain_text = re.sub(r"&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]+);",
                        lambda match: html.unescape(match.group()), plain_text)
    for match in URL_PATTERN.finditer(plain_text):
        url = match.group().rstrip(".,;\"'")
        for opening, closing in (("(", ")"), ("[", "]"), ("{", "}")):
            while url.endswith(closing) and url.count(closing) > url.count(opening):
                url = url[:-1]
        if _is_http_url(url):
            urls.append(url)
    if urls:
        for url in urls:
            yield {"url": url, "text": url}
    elif plain_text.strip():
        yield {"url": None, "text": plain_text.strip()}


def reference_items(value):
    """Return individual HTTP(S) links or escaped, non-clickable reference text."""
    result = []
    seen = set()
    for item in _items(value):
        identity = (item["url"], item["text"])
        if identity not in seen:
            result.append(item)
            seen.add(identity)
    return result


def serialize_references(*values):
    """Store report reference fields as a deduplicated JSON list."""
    return json.dumps([item["text"] for item in reference_items(values)], ensure_ascii=False)
