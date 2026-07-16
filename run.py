"""Run the aggregator.

    python run.py --demo    ingest bundled sample data (offline, safe)
    python run.py --live    fetch the real feeds and ingest

Live mode pulls from Abuse.ch and CISA. Sample data uses RFC 5737
documentation IP ranges (203.0.113.0/24, 198.51.100.0/24) so nothing in
the demo dataset points at real infrastructure.
"""

import argparse
import sys

from tfa.db import ThreatDB
from tfa import feeds, analyse, dashboard

SAMPLES = {
    "urlhaus": "sample_data/urlhaus_recent.csv",
    "feodo": "sample_data/feodo_ipblocklist.json",
    "cisa_kev": "sample_data/cisa_kev.json",
}


def main():
    ap = argparse.ArgumentParser()
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--demo", action="store_true", help="use bundled sample data")
    mode.add_argument("--live", action="store_true", help="fetch real feeds")
    ap.add_argument("--db", default="threats.db")
    args = ap.parse_args()

    db = ThreatDB(args.db)

    for name in feeds.FEEDS:
        try:
            if args.demo:
                with open(SAMPLES[name]) as f:
                    raw = f.read()
            else:
                print(f"fetching {name} ...")
                raw = feeds.fetch(name)
            n = feeds.ingest(db, name, raw)
            print(f"  {name}: {n} sightings ingested")
        except Exception as e:
            # one broken feed must not sink the run
            print(f"  {name}: FAILED ({e})", file=sys.stderr)

    print("\n-- summary --")
    for row in analyse.summary(db):
        print(f"  {row['type']:<8} {row['indicators']:>5} indicators "
              f"({row['sightings']} sightings)")

    corr = analyse.corroborated(db)
    print(f"\n-- corroborated by 2+ feeds: {len(corr)} --")
    for row in corr[:10]:
        print(f"  {row['value']:<22} [{row['type']}] seen by: {row['feeds']}")

    path = dashboard.save(db)
    print(f"\nDashboard written to {path}")
    db.close()


if __name__ == "__main__":
    main()
