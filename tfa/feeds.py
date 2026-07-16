"""Parsers for public threat feeds.

Three feeds, chosen because they need no API key and cover different
indicator types:

- Abuse.ch URLhaus  — recent malware distribution URLs (CSV)
- Abuse.ch Feodo    — botnet C2 IP blocklist (JSON)
- CISA KEV          — Known Exploited Vulnerabilities catalog (JSON)

Each parser takes raw feed text and yields (value, type, reported_at,
context) tuples. Fetching is separated from parsing so the parsers are
testable offline against saved samples, and so a fetch failure in one
feed never corrupts the ingest of another.
"""

import csv
import io
import json
import urllib.request
from urllib.parse import urlparse

FEEDS = {
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "description": "Abuse.ch URLhaus — recent malware distribution URLs",
    },
    "feodo": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "description": "Abuse.ch Feodo Tracker — botnet C2 IPs",
    },
    "cisa_kev": {
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "description": "CISA Known Exploited Vulnerabilities catalog",
    },
}


def fetch(feed_name, timeout=30):
    url = FEEDS[feed_name]["url"]
    req = urllib.request.Request(url, headers={"User-Agent": "tfa/0.1 (research)"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def parse_urlhaus(raw):
    # CSV with '#' comment header; columns:
    # id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
    lines = [l for l in raw.splitlines() if l and not l.startswith("#")]
    reader = csv.reader(io.StringIO("\n".join(lines)))
    for row in reader:
        if len(row) < 7:
            continue
        context = f"threat={row[5]} tags={row[6]}"
        yield row[2], "url", row[1], context
        # Derive a host-level indicator from each URL so cross-feed
        # correlation with IP blocklists is possible: a URL and a C2 IP
        # never match as strings, but their hosts do.
        host = urlparse(row[2]).hostname
        if host:
            host_type = "ip" if _looks_like_ip(host) else "domain"
            yield host, host_type, row[1], context + " derived_from=url"


def _looks_like_ip(host):
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() and int(p) < 256 for p in parts)


def parse_feodo(raw):
    for entry in json.loads(raw):
        context = f"malware={entry.get('malware', '?')} status={entry.get('status', '?')}"
        yield entry["ip_address"], "ip", entry.get("first_seen"), context


def parse_cisa_kev(raw):
    data = json.loads(raw)
    for vuln in data.get("vulnerabilities", []):
        context = (f"{vuln.get('vendorProject', '?')} {vuln.get('product', '?')}: "
                   f"{vuln.get('vulnerabilityName', '')}")
        yield vuln["cveID"], "cve", vuln.get("dateAdded"), context


PARSERS = {
    "urlhaus": parse_urlhaus,
    "feodo": parse_feodo,
    "cisa_kev": parse_cisa_kev,
}


def ingest(db, feed_name, raw):
    """Parse raw feed content and store every sighting. Returns count."""
    feed_id = db.register_feed(feed_name, FEEDS[feed_name]["url"],
                               FEEDS[feed_name]["description"])
    count = 0
    for value, ioc_type, reported_at, context in PARSERS[feed_name](raw):
        db.add_sighting(feed_id, value, ioc_type, reported_at, context)
        count += 1
    return count
