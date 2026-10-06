Run from the repository root with Python 3.10 or newer. No dependencies, accounts,
payments, scheduled jobs or outbound customer communications are created.

```
python3 -m sitewatch demo --output web/demo
python3 -m sitewatch run --config /path/to/authorized.json --output /path/to/report
python3 -m unittest discover -s tests -v
```

The demo uses synthetic fixtures and makes no network requests. It represents no
customer activity, payment or earned revenue. Each output directory receives
`report.html` and `report.json`. Reusing a directory compares with its prior
report only when the simulation flag and site scope match.

A real run requires explicit owner authorization both globally and for every
site. Authorization covers checks on that URL's origin, including same-origin
links and images. Obtain this permission before creating a configuration:

```json
{
  "authorized": true,
  "sites": [
    {"name": "Owner's website", "url": "https://owner.example/", "authorized": true}
  ],
  "limits": {"max_pages": 5, "max_checks": 30, "max_seconds": 120}
}
```

Limits apply to the entire run, across all configured sites. Defaults are five
pages, 30 requests (including robots and redirects), 256 KiB per response,
eight seconds per connection/read timeout, one second between requests and a
120-second elapsed-time budget. Hard caps are ten pages, 60 requests, 1 MiB per
response, 15-second timeout and 300-second budget. Each parsed page contributes
at most 200 links; at most 200 distinct resources per site are inspected. DNS
resolution and a currently blocked socket read can extend wall-clock time past
the elapsed-time budget. Redirects are limited to three per request and obey the
same public-IP, same-origin, robots, request-budget and rate rules.

Robots retrieval failures skip that site. Robots crawl delays and request rates
increase the configured interval. Requests use normal TLS certificate validation
and bypass environment proxy settings. Every resolved address must be global.
DNS is validated before the connection but is not pinned: this is not a network
isolation boundary or protection against every DNS rebinding scenario. Use
restricted egress when processing untrusted configuration. Do not use local or
private network destinations.

Reports prioritize observed HTTP failures and missing HTML fragments. Missing
titles are warnings; descriptions and canonical tags are informational. A
noindex directive can be intentional. Network failures remain unconfirmed and
are not proof of a broken link. JavaScript, login-protected content, outside
origins, full SEO, accessibility and legal compliance are outside scope.

Prior findings become resolved only with relevant fresh, successful, complete
evidence. Earlier findings with unavailable or omitted pages/resources stay
unverified. Fragment resolution requires the fragment ID in parsed HTML; a
successful HEAD is insufficient. Changed coverage and bounded scans can leave
findings unverified even when the underlying issue has actually been fixed.
