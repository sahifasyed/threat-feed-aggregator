import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tfa.db import ThreatDB
from tfa import feeds, analyse


URLHAUS_SAMPLE = '''# comment
"1","2026-07-10 01:00:00","http://203.0.113.5/mal.sh","online","","malware_download","mozi,elf","https://x/1/","r"
"2","2026-07-11 02:00:00","http://evil.example/drop.exe","online","","malware_download","lokibot","https://x/2/","r"
'''

FEODO_SAMPLE = '[{"ip_address":"203.0.113.5","port":443,"status":"online","malware":"QakBot","first_seen":"2026-07-09 04:00:00"}]'

KEV_SAMPLE = '{"vulnerabilities":[{"cveID":"CVE-2021-44228","vendorProject":"Apache","product":"Log4j","vulnerabilityName":"Log4Shell","dateAdded":"2026-07-11"}]}'


def make_db(tmp_path):
    return ThreatDB(str(tmp_path / "t.db"))


def test_urlhaus_derives_host_indicators(tmp_path):
    db = make_db(tmp_path)
    n = feeds.ingest(db, "urlhaus", URLHAUS_SAMPLE)
    # 2 URLs + 1 derived ip + 1 derived domain
    assert n == 4
    types = {r["type"] for r in analyse.summary(db)}
    assert types == {"url", "ip", "domain"}


def test_cross_feed_corroboration(tmp_path):
    db = make_db(tmp_path)
    feeds.ingest(db, "urlhaus", URLHAUS_SAMPLE)
    feeds.ingest(db, "feodo", FEODO_SAMPLE)
    corr = analyse.corroborated(db)
    assert len(corr) == 1
    assert corr[0]["value"] == "203.0.113.5"
    assert corr[0]["feed_count"] == 2


def test_duplicate_sightings_not_double_counted(tmp_path):
    db = make_db(tmp_path)
    feeds.ingest(db, "feodo", FEODO_SAMPLE)
    feeds.ingest(db, "feodo", FEODO_SAMPLE)   # same feed, same data
    rows = analyse.summary(db)
    ip_row = next(r for r in rows if r["type"] == "ip")
    assert ip_row["indicators"] == 1
    assert ip_row["sightings"] == 1           # UNIQUE constraint held


def test_kev_parsing(tmp_path):
    db = make_db(tmp_path)
    feeds.ingest(db, "cisa_kev", KEV_SAMPLE)
    cves = analyse.recent(db, "cve")
    assert cves[0]["value"] == "CVE-2021-44228"
    assert "Log4j" in cves[0]["context"]


def test_dashboard_renders(tmp_path):
    from tfa import dashboard
    db = make_db(tmp_path)
    feeds.ingest(db, "urlhaus", URLHAUS_SAMPLE)
    feeds.ingest(db, "feodo", FEODO_SAMPLE)
    feeds.ingest(db, "cisa_kev", KEV_SAMPLE)
    html = dashboard.render(db)
    assert "THREAT FEED" in html
    assert "203.0.113.5" in html      # corroborated IP appears
    assert "CVE-2021-44228" in html
