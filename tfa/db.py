"""SQLite storage for normalised threat indicators.

Schema notes: indicators are deduplicated on (value, type). Each sighting
of an indicator by a feed is a separate row in `sightings`, which is what
makes cross-feed corroboration queries possible — an IOC seen by two
independent feeds is worth more than one seen by a single feed twice.
SQLite is used so the demo runs with zero setup; the schema ports to
PostgreSQL unchanged apart from AUTOINCREMENT syntax.
"""

import sqlite3
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS feeds (
    feed_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    url         TEXT,
    description TEXT
);

CREATE TABLE IF NOT EXISTS indicators (
    indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
    value        TEXT NOT NULL,
    type         TEXT NOT NULL CHECK (type IN
                 ('ip', 'domain', 'url', 'sha256', 'md5', 'cve')),
    first_seen   TEXT NOT NULL,
    UNIQUE (value, type)
);

CREATE TABLE IF NOT EXISTS sightings (
    sighting_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator_id INTEGER NOT NULL REFERENCES indicators(indicator_id),
    feed_id      INTEGER NOT NULL REFERENCES feeds(feed_id),
    reported_at  TEXT,
    context      TEXT,
    ingested_at  TEXT NOT NULL,
    UNIQUE (indicator_id, feed_id, reported_at)
);

CREATE INDEX IF NOT EXISTS idx_sightings_indicator ON sightings(indicator_id);
CREATE INDEX IF NOT EXISTS idx_indicators_type ON indicators(type);
"""


class ThreatDB:
    def __init__(self, path="threats.db"):
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def register_feed(self, name, url="", description=""):
        self.conn.execute(
            "INSERT OR IGNORE INTO feeds (name, url, description) VALUES (?, ?, ?)",
            (name, url, description),
        )
        self.conn.commit()
        row = self.conn.execute(
            "SELECT feed_id FROM feeds WHERE name = ?", (name,)
        ).fetchone()
        return row["feed_id"]

    def add_sighting(self, feed_id, value, ioc_type, reported_at=None, context=""):
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "INSERT OR IGNORE INTO indicators (value, type, first_seen) VALUES (?, ?, ?)",
            (value, ioc_type, reported_at or now),
        )
        row = self.conn.execute(
            "SELECT indicator_id FROM indicators WHERE value = ? AND type = ?",
            (value, ioc_type),
        ).fetchone()
        self.conn.execute(
            "INSERT OR IGNORE INTO sightings "
            "(indicator_id, feed_id, reported_at, context, ingested_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (row["indicator_id"], feed_id, reported_at, context, now),
        )
        self.conn.commit()

    def query(self, sql, params=()):
        return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def close(self):
        self.conn.close()
