import json
from types import SimpleNamespace

from bs4 import BeautifulSoup
from django.template.loader import render_to_string
from django.test import SimpleTestCase

from utility.references import reference_items


class ReferenceRenderingTests(SimpleTestCase):
    urls = [
        "https://access.redhat.com/security/cve/CVE-2019-10747",
        "https://bugzilla.redhat.com/show_bug.cgi?id=1795475",
        "https://lists.apache.org/thread.html/report@<dev.drat.apache.org>",
        "https://example.test/advisory?id=123&source=scan#details",
    ]

    def links(self, value):
        markup = render_to_string("base/_references.html", {"value": value})
        return BeautifulSoup(markup, "html.parser")

    def test_existing_trivy_python_list_and_json_are_separate_absolute_links(self):
        for value in (self.urls, repr(self.urls), json.dumps(self.urls)):
            with self.subTest(value=value):
                anchors = self.links(value).select("a")
                self.assertEqual([anchor["href"] for anchor in anchors], self.urls)
                self.assertTrue(all(anchor["target"] == "_blank" for anchor in anchors))
                self.assertTrue(all("noopener" in anchor["rel"] for anchor in anchors))

    def test_single_url_preserves_query_fragment_and_apostrophe(self):
        url = "https://example.test/O'Reilly?id=123&source=scan&copy=1&not=2#details"
        self.assertEqual(self.links(url).a["href"], url)

    def test_plain_text_references_and_html_references(self):
        urls = self.urls[:2]
        for value in ("\n".join(urls), " ".join(urls), "<p>%s</p><p>%s</p>" % tuple(urls),
                      "%s<br>%s" % tuple(urls), '<a href="%s">Advisory</a><br>%s' % tuple(urls)):
            with self.subTest(value=value):
                self.assertEqual([anchor["href"] for anchor in self.links(value).select("a")], urls)

    def test_references_do_not_turn_unsafe_schemes_or_markup_into_links(self):
        markup = self.links(["javascript:alert(1)", "data:text/html,test", "/relative/path",
                             '<a href="javascript:alert(1)">Unsafe</a>',
                             '<img src=x onerror="alert(1)">', self.urls[0]])
        self.assertEqual([anchor["href"] for anchor in markup.select("a")], self.urls[:1])
        self.assertIsNone(markup.select_one("img, script, [onerror]"))

    def test_missing_references_and_plain_labels(self):
        for value in (None, "", "[]", []):
            self.assertEqual(reference_items(value), [])
            self.assertIn("No references provided.", self.links(value).get_text())
        self.assertEqual(reference_items("Not Found"), [{"url": None, "text": "Not Found"}])

    def test_duplicate_links_and_punctuation(self):
        value = 'See (%s), then [%s]. %s' % (self.urls[0], self.urls[1], self.urls[0])
        self.assertEqual([item["url"] for item in reference_items(value)], self.urls[:2])

    def test_detail_pages_render_legacy_references_with_the_shared_component(self):
        finding = SimpleNamespace(title="Reference regression", references=repr(self.urls),
                                  reference=repr(self.urls), instance="[]", scanner="Zap")
        templates = (
            ("staticscanners/scans/vuln_details.html", "vul_dat"),
            ("networkscanners/scans/vuln_details.html", "vul_dat"),
            ("cloudscanners/scans/vuln_details.html", "vul_dat"),
            ("webscanners/scans/vuln_details.html", "vul_dat"),
            ("pentest/manual_vuln_data.html", "vuln_detail"),
        )
        for template, key in templates:
            with self.subTest(template=template):
                markup = render_to_string(template, {key: [finding], "jira_projects": None})
                anchors = BeautifulSoup(markup, "html.parser").select('.accordion a[target="_blank"]')
                self.assertEqual([anchor["href"] for anchor in anchors], self.urls)
