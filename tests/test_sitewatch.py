import email.message
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.request

from sitewatch.engine import (DEFAULTS, Fetcher, GuardError, Page, RedirectGuard,
                              audit, clean_url, delta, demo, finding, load_config,
                              origin, page_findings, public_url, write_report)


ROOT = "https://example.com/"


def response(url=ROOT, status=200, body="", error=None, content_type="text/html"):
    return dict(url=url, status=status, body=body, error=error,
                content_type=content_type, truncated=False)


class FixtureFetcher:
    def __init__(self, fixtures):
        self.fixtures, self.checks, self.calls = fixtures, 0, []

    def fetch(self, url, expected_origin, method="GET", interval=None):
        self.checks += 1
        self.calls.append((url, method, interval))
        return self.fixtures[url]


class MemoryResponse(io.BytesIO):
    def __init__(self, content):
        super().__init__(content)
        self.status = 200
        self.headers = email.message.Message()
        self.headers["Content-Type"] = "text/html; charset=utf-8"

    def geturl(self):
        return ROOT


class SitewatchTests(unittest.TestCase):
    def test_parser_metadata_links_and_fragments(self):
        page = Page("<TITLE>Hello &amp; world</TITLE><META NAME='description' CONTENT='Intro'>"
                    "<meta name='robots' content='follow, NOINDEX'><link rel='alternate canonical' href='/'>"
                    "<base href='/docs/'><a id='here' name='old' href='other#part'>Go</a><img src='a.png'>")
        self.assertEqual(page.title, "Hello & world")
        self.assertEqual(page.description, "Intro")
        self.assertTrue(page.noindex)
        self.assertEqual(page.canonical, "/")
        self.assertEqual(page.base, "/docs/")
        self.assertEqual(page.ids, {"here", "old"})
        self.assertEqual(page.links, [("a", "other#part"), ("img", "a.png")])

    def test_truncated_metadata_is_not_reported_as_absent(self):
        self.assertEqual([f["code"] for f in page_findings(ROOT, Page(""), True)], ["truncated"])
        findings = page_findings(ROOT, Page("<title> </title>"))
        self.assertEqual({f["code"] for f in findings},
                         {"missing_title", "missing_description", "missing_canonical"})
        self.assertEqual(findings[0]["id"], page_findings(ROOT, Page(""))[0]["id"])
        self.assertTrue(page_findings(ROOT, Page('<meta name><meta name="description" content><link rel="canonical" href>')))

    def test_audit_broken_resources_and_unconfirmed_network(self):
        fixtures = {
            ROOT + "robots.txt": response(ROOT + "robots.txt", 404),
            ROOT: response(body="<title>Home</title><a href='/gone'>Lost</a><a href='/slow'>Slow</a>"
                           "<img src='/photo'><a href='https://outside.example/'>External</a>"),
            ROOT + "gone": response(ROOT + "gone", 404),
            ROOT + "slow": response(ROOT + "slow", None, error="timed out"),
            ROOT + "photo": response(ROOT + "photo", 404),
        }
        fetcher = FixtureFetcher(fixtures)
        observations, findings = audit([dict(name="Test", url=ROOT)], dict(DEFAULTS, max_pages=1), fetcher)
        by_code = {f["code"] for f in findings}
        self.assertIn("broken_link", by_code)
        self.assertIn("broken_image", by_code)
        self.assertIn("resource_unconfirmed", by_code)
        self.assertFalse(any(f["code"] == "broken_link" and f["target"].endswith("slow") for f in findings))
        self.assertTrue(all(origin(url) == origin(ROOT) for url, method, interval in fetcher.calls))
        self.assertEqual(findings[0]["severity"], "error")
        self.assertEqual(len(observations), 5)

    def test_robots_and_crawl_delay_are_observed(self):
        fetcher = FixtureFetcher({
            ROOT + "robots.txt": response(ROOT + "robots.txt", body="User-agent: *\nDisallow: /private\nCrawl-delay: 4"),
            ROOT: response(body="<title>Home</title><a href='/private'>Private</a><img src='/ok'>"),
            ROOT + "ok": response(ROOT + "ok"),
        })
        audit([dict(name="Test", url=ROOT)], dict(DEFAULTS), fetcher)
        self.assertNotIn(ROOT + "private", [call[0] for call in fetcher.calls])
        self.assertTrue(all(call[2] == 4 for call in fetcher.calls[1:]))

    def test_access_restrictions_not_proven_broken_and_known_errors_survive_body_failure(self):
        for status in (401, 403, 429):
            fetcher = FixtureFetcher({ROOT + "robots.txt": response(ROOT + "robots.txt", 404),
                                     ROOT: response(body="<title>Home</title><a href='/item'>Item</a><img src='/item'>"),
                                     ROOT + "item": response(ROOT + "item", status)})
            _, findings = audit([dict(name="Test", url=ROOT)], dict(DEFAULTS, max_pages=1), fetcher)
            self.assertIn("resource_restricted", {f["code"] for f in findings})
            self.assertFalse(any(f["code"] in ("broken_link", "broken_image") for f in findings))
            fetcher = FixtureFetcher({ROOT + "robots.txt": response(ROOT + "robots.txt", 404), ROOT: response(status=status)})
            _, findings = audit([dict(name="Test", url=ROOT)], DEFAULTS, fetcher)
            self.assertEqual(findings[0]["code"], "page_restricted")
        fetcher = FixtureFetcher({ROOT + "robots.txt": response(ROOT + "robots.txt", 404),
                                 ROOT: response(status=500, error="Unreadable body")})
        self.assertEqual(audit([dict(name="Test", url=ROOT)], DEFAULTS, fetcher)[1][0]["severity"], "error")

    def test_failed_robots_stops_site_and_anchor_fragments_checked(self):
        fetcher = FixtureFetcher({ROOT + "robots.txt": response(ROOT + "robots.txt", 503)})
        observations, findings = audit([dict(name="Test", url=ROOT)], DEFAULTS, fetcher)
        self.assertEqual(fetcher.checks, 1)
        self.assertEqual(findings[0]["code"], "robots_unavailable")
        fetcher = FixtureFetcher({ROOT + "robots.txt": response(ROOT + "robots.txt", 404),
                                 ROOT: response(body="<title>A</title><a href='#lost'>Jump</a><div id='ok'></div>")})
        _, findings = audit([dict(name="Test", url=ROOT)], DEFAULTS, fetcher)
        self.assertIn("missing_fragment", {f["code"] for f in findings})

    def test_authorization_required_globally_and_per_site(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"
            for data in ({"sites": []}, {"authorized": True, "sites": [{"name": "T", "url": ROOT}]},
                         {"authorized": True, "sites": [{"name": "T", "url": ROOT, "authorized": "true"}]}):
                config.write_text(json.dumps(data))
                self.assertRaises(ValueError, load_config, config)
            config.write_text(json.dumps(dict(authorized=True, sites=[dict(name="T", url=ROOT, authorized=True)])))
            self.assertEqual(load_config(config)[0][0]["url"], ROOT)

    def test_public_url_checks_all_addresses_and_origin(self):
        def addresses(*args, **kwargs):
            return [(2, 1, 6, "", ("93.184.216.34", 443))]
        self.assertEqual(public_url(ROOT, resolver=addresses), ROOT)
        self.assertRaises(GuardError, public_url, ROOT, origin("https://other.example"), addresses)
        for address in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "100.64.0.1", "::ffff:127.0.0.1"):
            resolver = lambda *a, ip=address, **k: addresses() + [(2, 1, 6, "", (ip, 443))]
            self.assertRaises(GuardError, public_url, ROOT, None, resolver)
        for url in ("file:///etc/passwd", "https://u:p@example.com/", "https://example.com:99999/", "https://example.com/\n"):
            self.assertRaises(ValueError, clean_url, url)

    def test_redirects_revalidate_origin_ip_and_count(self):
        def validator(url, expected):
            return public_url(url, expected, lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443))])
        guard = RedirectGuard(origin(ROOT), validator)
        request = urllib.request.Request(ROOT)
        redirected = guard.redirect_request(request, None, 302, "Found", {}, ROOT + "next")
        self.assertEqual(redirected.sitewatch_redirects, 1)
        self.assertRaises(GuardError, guard.redirect_request, request, None, 302, "Found", {}, "https://other.example/")
        request.sitewatch_redirects = 3
        self.assertRaises(GuardError, guard.redirect_request, request, None, 302, "Found", {}, ROOT)
        private = RedirectGuard(origin(ROOT), lambda u, o: public_url(u, o, lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 443))]))
        self.assertRaises(GuardError, private.redirect_request, request, None, 302, "Found", {}, ROOT)

    def test_redirect_gate_enforces_robots_delay_and_budget(self):
        import urllib.robotparser
        now, sleeps = [0], []
        def sleep(value):
            sleeps.append(value)
            now[0] += value
        fetcher = Fetcher(dict(DEFAULTS, max_checks=2), validator=lambda u, o: clean_url(u),
                          monotonic=lambda: now[0], sleeper=sleep)
        robots = urllib.robotparser.RobotFileParser()
        robots.parse(["User-agent: *", "Disallow: /private"])
        fetcher.set_policy(origin(ROOT), robots, 4)
        fetcher.before_request(ROOT, origin(ROOT))
        gate = RedirectGuard(origin(ROOT), lambda u, o: clean_url(u),
                             lambda u: fetcher.before_request(u, origin(ROOT)))
        request = urllib.request.Request(ROOT)
        self.assertRaises(GuardError, gate.redirect_request, request, None, 302, "Found", {}, ROOT + "private")
        gate.redirect_request(request, None, 302, "Found", {}, ROOT + "ok")
        self.assertEqual(sleeps, [4])
        self.assertEqual(fetcher.checks, 2)
        self.assertRaises(GuardError, gate.redirect_request, request, None, 302, "Found", {}, ROOT + "another")

    def test_fetch_limits_bytes_requests_and_rate(self):
        now, sleeps = [0], []
        def sleeper(value):
            sleeps.append(value)
            now[0] += value
        fetcher = Fetcher(dict(DEFAULTS, max_checks=2, max_bytes=8),
                          validator=lambda u, o: clean_url(u), monotonic=lambda: now[0], sleeper=sleeper)
        with patch("urllib.request.build_opener") as build:
            build.return_value.open.side_effect = lambda *a, **k: MemoryResponse(b"0123456789")
            first = fetcher.fetch(ROOT, origin(ROOT))
            fetcher.fetch(ROOT, origin(ROOT))
            third = fetcher.fetch(ROOT, origin(ROOT))
        self.assertEqual(first["body"], "01234567")
        self.assertTrue(first["truncated"])
        self.assertEqual(sleeps, [1])
        self.assertEqual(build.call_count, 2)
        self.assertIn("limit", third["error"])
        now[0] = fetcher.deadline
        self.assertIn("limit", fetcher.fetch(ROOT, origin(ROOT))["error"])

    def test_delta_requires_current_evidence(self):
        previous = [finding("missing_title", ROOT, ROOT, "warning", "Missing")]
        current = [finding("noindex", ROOT, ROOT, "warning", "Noindex")]
        self.assertEqual(len(delta(current, previous)["resolved"]), 1)
        for observation in (response(error="timeout"), response(status=500), response(content_type="image/png"),
                            dict(response(), truncated=True)):
            result = delta(current, previous, [observation])
            self.assertEqual(result["resolved"], [])
            self.assertEqual(result["unverified"], previous)
        self.assertEqual(delta([], previous, [response()])["resolved"], previous)
        self.assertEqual(delta(previous, previous)["persisting"], previous)
        fragment = [finding("missing_fragment", ROOT, ROOT + "#part", "error", "Missing fragment")]
        self.assertEqual(delta([], fragment, [response()])["resolved"], [])
        self.assertEqual(delta([], fragment, [dict(response(), html_fragments=["part"])])["resolved"], fragment)

    def test_html_escaped_and_demo_never_fetches(self):
        with tempfile.TemporaryDirectory() as directory:
            payload = "<script>alert('x')</script>"
            dangerous = finding("test", ROOT + payload, ROOT + payload, "error", payload)
            write_report(directory, [dict(url=ROOT)], DEFAULTS, [], [dangerous])
            rendered = (Path(directory) / "report.html").read_text()
            self.assertNotIn("<script>", rendered)
            self.assertIn("&lt;script&gt;", rendered)
            with patch.object(Fetcher, "fetch", side_effect=AssertionError("Network must not run")):
                report = demo(directory)
            self.assertTrue(report["simulated"])
            self.assertIn("SIMULATED DEMO", (Path(directory) / "report.html").read_text())
            self.assertIn("+00:00", report["observed_at"])
            report = demo(directory)
            self.assertEqual(len(report["changes"]["persisting"]), 3)

    def test_unverified_findings_survive_three_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            original = finding("broken_link", ROOT, ROOT + "old", "error", "HTTP 404")
            sites = [dict(url=ROOT)]
            write_report(directory, sites, DEFAULTS, [dict(response(), kind="page")], [original])
            unavailable = dict(response(status=None, error="timeout"), kind="page")
            second = write_report(directory, sites, DEFAULTS, [unavailable], [])
            third = write_report(directory, sites, DEFAULTS, [unavailable], [])
            self.assertEqual(second["changes"]["unverified"], [original])
            self.assertEqual(third["changes"]["unverified"], [original])
            self.assertEqual(third["changes"]["resolved"], [])
            recovered = write_report(directory, sites, DEFAULTS, [dict(response(), kind="page"), dict(response(ROOT + "old"), kind="resource")], [])
            self.assertEqual(recovered["changes"]["resolved"], [original])

    def test_report_links_only_safe_http_urls_and_escapes_attributes(self):
        with tempfile.TemporaryDirectory() as directory:
            safe = ROOT + '?q="quoted"&next=ok'
            entries = [finding("test", safe, "javascript:alert(1)", "info", "Check"),
                       finding("test", ROOT, "data:text/html,<script>x</script>", "info", "Check")]
            write_report(directory, [dict(url=ROOT)], DEFAULTS, [], entries)
            rendered = (Path(directory) / "report.html").read_text()
            self.assertIn('href="https://example.com/?q=&quot;quoted&quot;&amp;next=ok"', rendered)
            self.assertNotIn('href="javascript:', rendered)
            self.assertNotIn('href="data:', rendered)
            self.assertIn("data:text/html,&lt;script&gt;x&lt;/script&gt;", rendered)


if __name__ == "__main__":
    unittest.main()
