# Portfolio QA reports

A free, dependency-free Python tool for bounded website checks and readable HTML reports. It helps you review observed page errors, internal links, image URLs and changes from a previous scan.

**[Explore the simulated sample report](https://gennarobaratta.github.io/portfolio-qa-reports/demo/report.html)** · **[Project documentation](https://gennarobaratta.github.io/portfolio-qa-reports/)**

## Quick start

Python 3.10 or newer, standard library only:

```bash
python3 -m sitewatch demo --output reports/demo
python3 -m unittest discover -s tests -v
```

Open `reports/demo/report.html` in a browser. The demo makes no network requests and represents no actual customer observations.

For real checks, obtain permission for every site first. Read [the engine guide](sitewatch/README.md), create a configuration outside the public documentation, then run:

```bash
python3 -m sitewatch run --config authorized.json --output reports/my-site
```

Limits apply across a whole run: run sites separately when each needs its own budget. Honor site owners' wishes and retain reports privately.

## What it reports

- Observed HTTP errors and same-origin link/image responses.
- Missing HTML fragment destinations, titles, descriptions and canonicals; informational metadata can be intentional.
- HTML noindex directives that need review.
- New, persistent, resolved and unverified findings compared with prior compatible results. Unavailable checks do not prove resolution.
- Scan observations and limits alongside the findings.

Access restrictions and rate limits are warnings, rather than proof of broken resources. All reported URLs are evidence of a bounded observation, not a promise about a website's future behavior.

## Scope

Only public static HTML and same-origin resources are checked. This does not execute JavaScript or test logins, forms, payment flows, accessibility compliance, security, SEO rankings or uptime. Normal TLS verification, public-IP guards, bounded sequential requests and robots rules are applied. DNS is checked but not pinned; this tool is not a network isolation boundary. See the engine guide before handling untrusted input.

This project documentation and sample are free. They accept no payments, create no accounts and offer no hosted scanning or support SLA.

## Feedback

Use [GitHub issues](https://github.com/GennaroBaratta/portfolio-qa-reports/issues) for bugs and report-format ideas. Everything posted there is public; omit client names, private URLs, credentials and confidential reports. Review GitHub's privacy policy before posting. An issue is not consent to sales messages.

MIT licensed. Copyright 2026 GennaroBaratta.
