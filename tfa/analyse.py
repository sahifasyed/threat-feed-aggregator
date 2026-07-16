"""Analysis queries over the aggregated indicator set.

These are the questions an analyst actually asks of a feed aggregate:
what's corroborated, what's new, what's trending. Kept as plain SQL so
the analytical logic is visible and portable.
"""


def summary(db):
    return db.query("""
        SELECT i.type, COUNT(DISTINCT i.indicator_id) AS indicators,
               COUNT(s.sighting_id) AS sightings
        FROM indicators i
        JOIN sightings s ON s.indicator_id = i.indicator_id
        GROUP BY i.type
        ORDER BY indicators DESC
    """)


def feed_totals(db):
    return db.query("""
        SELECT f.name, f.description,
               COUNT(DISTINCT s.indicator_id) AS indicators
        FROM feeds f
        LEFT JOIN sightings s ON s.feed_id = f.feed_id
        GROUP BY f.feed_id
        ORDER BY indicators DESC
    """)


def corroborated(db, min_feeds=2):
    """Indicators independently reported by two or more feeds —
    the highest-confidence subset of the aggregate."""
    return db.query("""
        SELECT i.value, i.type, COUNT(DISTINCT s.feed_id) AS feed_count,
               GROUP_CONCAT(DISTINCT f.name) AS feeds
        FROM indicators i
        JOIN sightings s ON s.indicator_id = i.indicator_id
        JOIN feeds f ON f.feed_id = s.feed_id
        GROUP BY i.indicator_id
        HAVING feed_count >= ?
        ORDER BY feed_count DESC, i.value
    """, (min_feeds,))


def recent(db, ioc_type, limit=15):
    return db.query("""
        SELECT i.value, i.first_seen, s.context, f.name AS feed
        FROM indicators i
        JOIN sightings s ON s.indicator_id = i.indicator_id
        JOIN feeds f ON f.feed_id = s.feed_id
        WHERE i.type = ?
        ORDER BY i.first_seen DESC
        LIMIT ?
    """, (ioc_type, limit))


def top_context_terms(db, ioc_type, limit=8):
    """Crude family/tag ranking from sighting context strings."""
    rows = db.query(
        "SELECT s.context FROM sightings s "
        "JOIN indicators i ON i.indicator_id = s.indicator_id "
        "WHERE i.type = ?", (ioc_type,))
    counts = {}
    for r in rows:
        parts = dict(p.split("=", 1) for p in r["context"].split() if "=" in p)
        # Feodo names the family directly. URLhaus doesn't: its `threat`
        # field is a category ("malware_download"), and the actual family
        # sits first in the tag list, so prefer tags over threat.
        family = parts.get("malware")
        if not family:
            tags = parts.get("tags", "")
            family = tags.split(",")[0] if tags else None
        if not family:
            family = parts.get("threat")
        if family and family.lower() not in ("none", "?", ""):
            counts[family] = counts.get(family, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: -kv[1])[:limit]
    return [{"name": k, "count": v} for k, v in ranked]
