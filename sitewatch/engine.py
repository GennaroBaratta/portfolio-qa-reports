"""Bounded website checks, not a network isolation boundary.

DNS is checked before urllib connects, but is not pinned; DNS rebinding and
resolver/network configuration remain deployment concerns. Run this tool in a
restricted egress environment when handling untrusted inputs. JavaScript,
authenticated content, accessibility, legal compliance, and full SEO are outside
scope. HTML observations are limited to the bytes and pages actually fetched.
"""

import argparse
import collections
import datetime
import hashlib
import html
import http.client
from html.parser import HTMLParser
import ipaddress
import json
from pathlib import Path
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
import urllib.robotparser

AGENT = "Sitewatch/0.1 (owner-authorized website checks)"
DEFAULTS = dict(max_pages=5, max_checks=30, max_bytes=262144,
                timeout=8, min_interval=1, max_seconds=120)
CAPS = dict(max_pages=10, max_checks=60, max_bytes=1048576,
            timeout=15, min_interval=30, max_seconds=300)


class GuardError(ValueError):
    pass


def origin(url):
    parts = urllib.parse.urlsplit(url)
    return parts.scheme.lower(), parts.hostname, parts.port or (443 if parts.scheme.lower() == "https" else 80)


def clean_url(url):
    if not isinstance(url, str) or any(ord(c) < 33 or ord(c) == 127 for c in url):
        raise GuardError("URL contains whitespace or control characters")
    parts = urllib.parse.urlsplit(url)
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        raise GuardError("Only absolute HTTP/HTTPS URLs are supported")
    if parts.username is not None or parts.password is not None:
        raise GuardError("URL credentials are forbidden")
    try:
        origin(url)
    except ValueError as exc:
        raise GuardError("Invalid URL port") from exc
    return urllib.parse.urlunsplit((parts.scheme.lower(), parts.netloc, parts.path or "/", parts.query, ""))


def public_url(url, expected_origin=None, resolver=socket.getaddrinfo):
    url = clean_url(url)
    if expected_origin is not None and origin(url) != expected_origin:
        raise GuardError("Cross-origin request refused")
    scheme, host, port = origin(url)
    try:
        addresses = resolver(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise GuardError("DNS resolution failed") from exc
    if not addresses:
        raise GuardError("DNS returned no addresses")
    for address in addresses:
        try:
            if not ipaddress.ip_address(address[4][0]).is_global:
                raise GuardError("Non-public destination refused")
        except ValueError as exc:
            raise GuardError("Invalid destination address") from exc
    return url


class RedirectGuard(urllib.request.HTTPRedirectHandler):
    def __init__(self, expected_origin, validator=public_url, before_redirect=None):
        self.expected_origin, self.validator = expected_origin, validator
        self.before_redirect = before_redirect

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        newurl = self.validator(newurl, self.expected_origin)
        count = getattr(req, "sitewatch_redirects", 0) + 1
        if count > 3:
            raise GuardError("Redirect limit reached")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None:
            if self.before_redirect:
                self.before_redirect(newurl)
            redirected.sitewatch_redirects = count
        return redirected


class Fetcher:
    def __init__(self, limits, validator=public_url, monotonic=time.monotonic, sleeper=time.sleep):
        self.limits, self.validator = limits, validator
        self.monotonic, self.sleeper = monotonic, sleeper
        self.deadline = monotonic() + limits["max_seconds"]
        self.last_request = None
        self.checks = 0
        self.policies = {}

    def set_policy(self, expected_origin, robots, interval):
        self.policies[expected_origin] = (robots, interval)

    def before_request(self, url, expected_origin, interval=0):
        if self.checks >= self.limits["max_checks"] or self.monotonic() >= self.deadline:
            raise GuardError("Run request/time limit reached")
        url = self.validator(url, expected_origin)
        policy = self.policies.get(expected_origin)
        if policy:
            robots, robot_interval = policy
            if not robots.can_fetch("Sitewatch", url):
                raise GuardError("Disallowed by robots.txt")
            interval = max(interval, robot_interval)
        delay = max(self.limits["min_interval"], interval)
        if self.last_request is not None:
            wait = max(0, self.last_request + delay - self.monotonic())
            if self.monotonic() + wait >= self.deadline:
                raise GuardError("Run time limit reached")
            self.sleeper(wait)
        self.checks += 1
        self.last_request = self.monotonic()
        return url

    def fetch(self, url, expected_origin, method="GET", interval=None):
        result = dict(url=url, status=None, body="", truncated=False, content_type="", error=None,
                      observed_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
        try:
            url = self.before_request(url, expected_origin, interval or 0)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                RedirectGuard(expected_origin, self.validator,
                                                              lambda u: self.before_request(u, expected_origin, interval or 0)))
            request = urllib.request.Request(url, method=method, headers={"User-Agent": AGENT})
            try:
                response = opener.open(request, timeout=min(self.limits["timeout"], self.deadline - self.monotonic()))
            except urllib.error.HTTPError as exc:
                response = exc
            with response:
                result.update(url=response.geturl(), status=response.status,
                              content_type=response.headers.get("Content-Type", ""))
                if method != "HEAD" and response.headers.get("Content-Encoding", "identity").lower() != "identity":
                    raise GuardError("Encoded response was not inspected")
                chunks, length = [], 0
                if method != "HEAD":
                    while length <= self.limits["max_bytes"]:
                        if self.monotonic() >= self.deadline:
                            raise GuardError("Run time limit reached during response")
                        chunk = response.read1(min(16384, self.limits["max_bytes"] + 1 - length))
                        if not chunk:
                            break
                        chunks.append(chunk)
                        length += len(chunk)
                data = b"".join(chunks)
                result["truncated"] = len(data) > self.limits["max_bytes"]
                encoding = response.headers.get_content_charset() or "utf-8"
                try:
                    result["body"] = data[:self.limits["max_bytes"]].decode(encoding, errors="replace")
                except LookupError:
                    result["body"] = data[:self.limits["max_bytes"]].decode("utf-8", errors="replace")
        except (ValueError, OSError, urllib.error.URLError, http.client.HTTPException) as exc:
            result["error"] = str(exc)
        return result


class Page(HTMLParser):
    def __init__(self, source):
        super().__init__(convert_charrefs=True)
        self.title, self.description, self.canonical, self.base = "", "", "", ""
        self.noindex, self.in_title = False, False
        self.links, self.ids = [], set()
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        attrs = {key: value or "" for key, value in attrs}
        if attrs.get("id"):
            self.ids.add(attrs["id"])
        if tag == "a" and attrs.get("name"):
            self.ids.add(attrs["name"])
        if tag == "title":
            self.in_title = True
        if tag == "base" and not self.base:
            self.base = attrs.get("href", "")
        if tag == "meta":
            name = attrs.get("name", "").lower()
            if name == "description":
                self.description = attrs.get("content", "")
            if name in ("robots", "googlebot"):
                directives = attrs.get("content", "").lower().replace(",", " ").split()
                self.noindex |= "noindex" in directives or "none" in directives
        if tag == "link" and "canonical" in attrs.get("rel", "").lower().split():
            self.canonical = attrs.get("href", "")
        if tag in ("a", "img"):
            href = attrs.get("href" if tag == "a" else "src")
            if href:
                self.links.append((tag, href))

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title += data


def finding(code, page, target, severity, message):
    identity = json.dumps([code, page, target], separators=(",", ":"))
    return dict(id=hashlib.sha256(identity.encode()).hexdigest()[:20], code=code,
                page=page, target=target, severity=severity, message=message)


def page_findings(url, parsed, truncated=False):
    results = []
    for missing, code, severity, message in (
        (not parsed.title.strip(), "missing_title", "warning", "Page title is missing or empty."),
        (not parsed.description.strip(), "missing_description", "info", "Meta description is missing or empty."),
        (not parsed.canonical.strip(), "missing_canonical", "info", "Canonical link is absent; it is optional for some pages."),
        (parsed.noindex, "noindex", "warning", "A robots meta directive requests no indexing; confirm this is intentional."),
    ):
        if missing and (not truncated or code == "noindex"):
            results.append(finding(code, url, url, severity, message))
    if truncated:
        results.append(finding("truncated", url, url, "info", "Response exceeded the byte limit; metadata absence was not assessed."))
    return results


def load_config(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("authorized") is not True:
        raise ValueError("Configuration must explicitly declare authorized: true")
    sites = data.get("sites")
    if not isinstance(sites, list) or not 1 <= len(sites) <= 10:
        raise ValueError("Configuration needs 1–10 sites")
    for site in sites:
        if not isinstance(site, dict) or site.get("authorized") is not True:
            raise ValueError("Each site must explicitly declare authorized: true")
        if not isinstance(site.get("name"), str) or not site["name"].strip():
            raise ValueError("Each site needs a name")
        site["url"] = clean_url(site.get("url"))
    limits = dict(DEFAULTS)
    custom = data.get("limits", {})
    if not isinstance(custom, dict) or set(custom) - set(limits):
        raise ValueError("Unknown or invalid limits")
    for key, value in custom.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= CAPS[key]:
            raise ValueError("Invalid bounded limit: " + key)
        if key in ("max_pages", "max_checks", "max_bytes") and not isinstance(value, int):
            raise ValueError("Limit must be an integer: " + key)
        limits[key] = value
    return sites, limits


def audit(sites, limits, fetcher=None):
    fetcher = fetcher or Fetcher(limits)
    observations, findings = [], []
    pages_used = 0
    for site in sites:
        root, expected = site["url"], origin(site["url"])
        robots_url = urllib.parse.urljoin(root, "/robots.txt")
        robots_result = fetcher.fetch(robots_url, expected)
        observations.append(dict(site=site["name"], kind="robots", **{k: v for k, v in robots_result.items() if k != "body"}))
        robots = urllib.robotparser.RobotFileParser()
        if robots_result["error"] or robots_result["truncated"] or robots_result["status"] not in (200, 404, 410):
            findings.append(finding("robots_unavailable", root, robots_url, "warning", "Robots policy could not be confirmed; this site was skipped."))
            continue
        robots.parse(robots_result["body"].splitlines() if robots_result["status"] == 200 else [])
        interval = robots.crawl_delay("Sitewatch") or 0
        rate = robots.request_rate("Sitewatch")
        if rate and rate.requests > 0:
            interval = max(interval, rate.seconds / rate.requests)
        if hasattr(fetcher, "set_policy"):
            fetcher.set_policy(expected, robots, interval)
        queue, seen, resources, parsed_pages, page_results = collections.deque([root]), set(), {}, {}, {}
        while queue and pages_used < limits["max_pages"] and fetcher.checks < limits["max_checks"]:
            url = queue.popleft()
            if url in seen:
                continue
            seen.add(url)
            if not robots.can_fetch("Sitewatch", url):
                observations.append(dict(site=site["name"], kind="page", url=url, error="Disallowed by robots.txt", status=None))
                continue
            result = fetcher.fetch(url, expected, interval=interval)
            page_results[url] = result
            pages_used += 1
            observation = dict(site=site["name"], kind="page", **{k: v for k, v in result.items() if k != "body"})
            observations.append(observation)
            if result["status"] in (401, 403, 429):
                findings.append(finding("page_restricted", url, url, "warning", "Access or rate restriction: HTTP " + str(result["status"]) + "; availability is unconfirmed."))
                continue
            if result["status"] is not None and result["status"] >= 400:
                findings.append(finding("page_http_error", url, url, "error", "Page returned HTTP " + str(result["status"]) + "."))
                continue
            if result["error"]:
                findings.append(finding("fetch_unconfirmed", url, url, "warning", "Page could not be checked: " + result["error"]))
                continue
            if "html" not in result["content_type"].lower():
                continue
            parsed = Page(result["body"])
            if not result["truncated"]:
                observation["html_fragments"] = sorted(parsed.ids)
            parsed_pages[url] = (parsed, result["truncated"])
            findings.extend(page_findings(url, parsed, result["truncated"]))
            base = urllib.parse.urljoin(result["url"], parsed.base) if parsed.base else result["url"]
            for kind, href in parsed.links[:200]:
                target = urllib.parse.urljoin(base, href)
                try:
                    target_url = clean_url(target)
                    if origin(target_url) != expected:
                        continue
                except ValueError:
                    continue
                resources.setdefault(target_url, []).append((url, kind, urllib.parse.urlsplit(target).fragment))
                if kind == "a" and target_url not in seen and target_url not in queue:
                    queue.append(target_url)
        for target, sources in list(resources.items())[:200]:
            if target in parsed_pages:
                parsed, truncated = parsed_pages[target]
                for source, kind, fragment in sources:
                    if kind == "a" and fragment and not truncated and urllib.parse.unquote(fragment) not in parsed.ids:
                        findings.append(finding("missing_fragment", source, target + "#" + fragment, "error", "Link points to a missing HTML fragment."))
            if target in page_results:
                result = page_results[target]
            else:
                if not robots.can_fetch("Sitewatch", target) or fetcher.checks >= limits["max_checks"]:
                    continue
                result = fetcher.fetch(target, expected, method="HEAD", interval=interval)
                if result["status"] in (405, 501) and not result["error"]:
                    result = fetcher.fetch(target, expected, interval=interval)
                observations.append(dict(site=site["name"], kind="resource", **{k: v for k, v in result.items() if k != "body"}))
            if result["status"] in (401, 403, 429):
                for source, kind, fragment in sources:
                    findings.append(finding("resource_restricted", source, target, "warning", "Access or rate restriction: HTTP " + str(result["status"]) + "; resource availability is unconfirmed."))
            elif result["status"] is not None and result["status"] >= 400:
                for source, kind, fragment in sources:
                    findings.append(finding("broken_image" if kind == "img" else "broken_link", source, target, "error", "Resource returned HTTP " + str(result["status"]) + "."))
            elif result["error"]:
                for source, kind, fragment in sources:
                    findings.append(finding("resource_unconfirmed", source, target, "warning", "Resource could not be verified: " + result["error"]))
    unique = {entry["id"]: entry for entry in findings}
    return observations, sorted(unique.values(), key=lambda f: ({"error": 0, "warning": 1, "info": 2}[f["severity"]], f["page"], f["code"]))


def delta(current, previous, observations=None):
    before = {f["id"]: f for f in previous}
    now = {f["id"]: f for f in current}
    coverage = {o["url"]: o for o in observations or [] if o.get("status") is not None
                and o["status"] < 400 and not o.get("error") and not o.get("truncated")}
    def verified(entry):
        if observations is None:
            return True
        page = coverage.get(entry["page"])
        if not page:
            return False
        if entry["code"] == "missing_fragment":
            target = coverage.get(clean_url(entry["target"]), {})
            fragment = urllib.parse.unquote(urllib.parse.urlsplit(entry["target"]).fragment)
            return fragment in target.get("html_fragments", []) and "html" in page.get("content_type", "")
        if entry["code"] in ("broken_link", "broken_image", "resource_unconfirmed", "resource_restricted"):
            return clean_url(entry["target"]) in coverage and "html" in page.get("content_type", "")
        if entry["code"] in ("missing_title", "missing_description", "missing_canonical", "noindex"):
            return "html" in page.get("content_type", "")
        return entry["code"] not in ("robots_unavailable", "truncated")
    missing = [before[k] for k in sorted(before.keys() - now.keys())]
    return dict(new=[now[k] for k in sorted(now.keys() - before.keys())],
                resolved=[entry for entry in missing if verified(entry)],
                unverified=[entry for entry in missing if not verified(entry)],
                persisting=[now[k] for k in sorted(now.keys() & before.keys())])


def render(report):
    esc = lambda value: html.escape(str(value), quote=True)
    def link(url):
        try:
            clean_url(url)
        except ValueError:
            return esc(url)
        return '<a href="' + esc(url) + '">' + esc(url) + '</a>'
    changes = report["changes"]
    rows = "".join("<tr><td data-label='Impact'><span class='badge " + esc(f["severity"]) + "'>" + esc(f["severity"]) + "</span></td><td data-label='Observation'>" + esc(f["message"]) + "<small>" + esc(f["code"]) + "</small></td><td data-label='Page and evidence'>" + link(f["page"]) + "<small>Evidence: " + link(f["target"]) + "</small></td></tr>" for f in report["findings"])
    observations = "".join("<tr><td>" + esc(o["kind"]) + "</td><td>" + link(o["url"]) + "</td><td>" + esc(o.get("error") or o.get("status") or "Not checked") + "</td></tr>" for o in report["observations"])
    resolved = "".join("<li>" + esc(f["message"]) + " — " + esc(f["page"]) + "</li>" for f in changes["resolved"])
    unverified = "".join("<li>" + esc(f["message"]) + " — " + esc(f["page"]) + "</li>" for f in changes["unverified"])
    label = "SIMULATED DEMO — no websites were contacted; no customers or payments are represented" if report["simulated"] else "Owner-authorized website observations"
    return """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Sitewatch health report</title><style>
    *{box-sizing:border-box}body{margin:0;background:#f3f5f8;color:#172536;font:15px/1.6 system-ui,sans-serif}main{max-width:1150px;margin:40px auto;padding:36px;background:#fff;border:1px solid #d8e0e9;border-radius:16px}h1{font-size:36px;margin:8px 0}h2{margin-top:34px;font-size:21px}.eyebrow{color:#24625c;font-weight:700;letter-spacing:.05em}.muted,small{color:#586879}small{display:block;font-size:12px}.summary{display:flex;flex-wrap:wrap;gap:16px;margin:24px 0}.card{background:#f3f5f8;padding:16px 24px;border-radius:10px;min-width:140px}.card strong{display:block;font-size:27px}table{border-collapse:collapse;width:100%;font-size:13px}th{text-align:left;color:#586879}td,th{padding:12px;border-bottom:1px solid #e0e6ed;vertical-align:top;overflow-wrap:anywhere}td:last-child{max-width:420px}.badge{display:inline-block;padding:3px 8px;border-radius:5px;font-weight:700;white-space:nowrap;overflow-wrap:normal}.error{background:#ffe4df;color:#923d30}.warning{background:#fff0cf;color:#7c5c10}.info{background:#e8eef5;color:#435971}footer{margin-top:36px;border-top:1px solid #e0e6ed;padding-top:16px;font-size:12px;color:#586879}@media(max-width:600px){main{margin:0;padding:20px;border:0;border-radius:0}td,th{padding:8px}.findings thead{display:none}.findings,.findings tbody,.findings tr,.findings td{display:block;width:100%}.findings tr{margin:12px 0;padding:12px 16px;border:1px solid #e0e6ed;border-radius:10px}.findings td{max-width:none;border:0;padding:6px 0}.findings td::before{content:attr(data-label);display:block;color:#586879;font-size:11px;font-weight:700}.evidence th:first-child,.evidence td:first-child{width:24%}.evidence th:last-child,.evidence td:last-child{width:30%}}a{color:#24625c;text-underline-offset:3px}@media print{body{background:white}main{border:0;margin:0;padding:0;max-width:none}tr{break-inside:avoid}.card{border:1px solid #ddd}h2{break-after:avoid}}
    </style><main><div class="eyebrow">SITEWATCH · """ + esc(label) + "</div><h1>Website health report</h1><p class='muted'>Observed " + esc(report["observed_at"]) + " · Static HTML checks</p><div class='summary'>" + "".join("<div class='card'><strong>" + str(sum(f["severity"] == severity for f in report["findings"])) + "</strong>" + severity.title() + " findings</div>" for severity in ("error", "warning", "info")) + "</div><p>Compared with the previous compatible report: " + str(len(changes["new"])) + " new · " + str(len(changes["persisting"])) + " persisting · " + str(len(changes["resolved"])) + " resolved · " + str(len(changes["unverified"])) + " not reverified.</p><h2>Findings, ordered by impact</h2><table class='findings'><thead><tr><th>Impact</th><th>Observation</th><th>Page and evidence URL</th></tr></thead><tbody>" + (rows or "<tr><td colspan='3'>No issues observed within the checks completed.</td></tr>") + "</tbody></table><h2>Resolved within checked coverage</h2><p>Relevant URLs were successfully rechecked; this remains a bounded observation.</p><ul>" + (resolved or "<li>None</li>") + "</ul><h2>Previous findings not reverified</h2><p>Unavailable pages, limits and coverage changes can leave earlier findings unverified.</p><ul>" + (unverified or "<li>None</li>") + "</ul><h2>Check evidence</h2><table class='evidence'><tr><th>Check</th><th>URL</th><th>HTTP status / limitation</th></tr>" + observations + "</table><footer><p>Limits: " + esc(json.dumps(report["limits"], sort_keys=True)) + "</p><p>Only fetched static HTML is assessed. At most 200 links per page and 200 distinct resources per site are considered. JavaScript, authenticated pages, external resources, accessibility and full SEO are outside scope. Network failures do not prove a broken link. Robots exclusions and configured limits reduce coverage. Canonicals and descriptions are informational checks, not universal requirements. Observation time is the run timestamp, not a guarantee of future availability.</p></footer></main></html>"


def write_report(output, sites, limits, observations, findings, simulated=False):
    directory = Path(output)
    directory.mkdir(parents=True, exist_ok=True)
    state = directory / "report.json"
    scope = dict(simulated=simulated, sites=[s["url"] for s in sites])
    previous = []
    if state.exists():
        try:
            old = json.loads(state.read_text(encoding="utf-8"))
            if not isinstance(old, dict):
                raise ValueError("Previous state must be an object")
            entries = old.get("findings", [])
            old_changes = old.get("changes", {})
            unverified = old_changes.get("unverified", []) if isinstance(old_changes, dict) else []
            if isinstance(entries, list) and isinstance(unverified, list):
                entries = unverified + entries
            required = {"id", "code", "page", "target", "severity", "message"}
            if (old.get("schema_version") == 1 and old.get("scope") == scope and isinstance(entries, list)
                    and all(isinstance(f, dict) and required <= f.keys()
                            and all(isinstance(f[key], str) for key in required) for f in entries)):
                previous = entries
        except (ValueError, OSError):
            pass
    report = dict(schema_version=1, observed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  simulated=simulated, scope=scope, sites=sites, limits=limits,
                  observations=observations, findings=findings, changes=delta(findings, previous, observations))
    (directory / "report.html").write_text(render(report), encoding="utf-8")
    state.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def demo(output):
    root = "https://demo.example/"
    source = "<title>Studio Juniper</title><meta name='description' content='Independent design studio'><link rel='canonical' href='https://demo.example/'><a href='/contact'>Contact</a><img src='/images/team.jpg'>"
    sites = [dict(name="Studio Juniper (synthetic fixture)", url=root, authorized=True)]
    findings = page_findings(root, Page(source))
    findings.extend([finding("broken_link", root, root + "contact", "error", "Simulated contact link returned HTTP 404."),
                     finding("broken_image", root, root + "images/team.jpg", "error", "Simulated team image returned HTTP 404."),
                     finding("noindex", root + "services", root + "services", "warning", "Simulated services page requests no indexing; confirm intent.")])
    observations = [dict(site=sites[0]["name"], kind="simulated page", url=root, status=200),
                    dict(site=sites[0]["name"], kind="simulated resource", url=root + "contact", status=404),
                    dict(site=sites[0]["name"], kind="simulated resource", url=root + "images/team.jpg", status=404)]
    return write_report(output, sites, DEFAULTS, observations, findings, simulated=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Owner-authorized, bounded static website health reports")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "demo"):
        command = commands.add_parser(name)
        command.add_argument("--output", required=True)
        if name == "run":
            command.add_argument("--config", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "demo":
            report = demo(args.output)
        else:
            sites, limits = load_config(args.config)
            observations, findings = audit(sites, limits)
            report = write_report(args.output, sites, limits, observations, findings)
        print("Wrote report.html and report.json to", args.output)
        print(len(report["findings"]), "findings;", "SIMULATED DATA" if report["simulated"] else "bounded static checks")
        return 0
    except (ValueError, OSError, TypeError) as exc:
        print("Sitewatch:", exc)
        return 2
