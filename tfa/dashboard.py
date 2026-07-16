"""Static HTML threat dashboard generator.

Produces a single self-contained HTML file from the aggregated database:
no JS frameworks, no external assets, opens anywhere. Deliberately styled
like a SOC wallboard — dark theme, stat cards, corroboration table.
"""

from datetime import datetime, timezone
from html import escape

from tfa import analyse

CSS = """
* { margin:0; padding:0; box-sizing:border-box; }
body { background:#0d1117; color:#c9d1d9;
       font-family:-apple-system,'Segoe UI',Roboto,sans-serif; padding:32px; }
h1 { color:#e6edf3; font-size:22px; letter-spacing:.5px; }
h1 span { color:#58a6ff; }
.sub { color:#8b949e; font-size:13px; margin:6px 0 28px; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
        gap:14px; margin-bottom:30px; }
.card { background:#161b22; border:1px solid #30363d; border-radius:8px;
        padding:18px; }
.card .n { font-size:30px; font-weight:700; color:#e6edf3; }
.card .l { font-size:12px; color:#8b949e; text-transform:uppercase;
           letter-spacing:1px; margin-top:4px; }
.card.hot .n { color:#f85149; }
.card.corr .n { color:#3fb950; }
h2 { font-size:14px; color:#8b949e; text-transform:uppercase;
     letter-spacing:1.5px; margin:26px 0 12px; }
table { width:100%; border-collapse:collapse; background:#161b22;
        border:1px solid #30363d; border-radius:8px; overflow:hidden; }
th { text-align:left; font-size:11px; color:#8b949e; text-transform:uppercase;
     letter-spacing:1px; padding:10px 14px; border-bottom:1px solid #30363d; }
td { padding:9px 14px; font-size:13px; border-bottom:1px solid #21262d;
     font-family:ui-monospace,'SF Mono',Menlo,monospace; }
tr:last-child td { border-bottom:none; }
td.type { color:#58a6ff; }
td.feeds { color:#3fb950; }
.bar-row { display:flex; align-items:center; gap:10px; margin:6px 0; }
.bar-label { width:170px; font-size:13px; font-family:ui-monospace,monospace;
             color:#c9d1d9; text-align:right; }
.bar { height:18px; background:linear-gradient(90deg,#1f6feb,#58a6ff);
       border-radius:3px; }
.bar-count { font-size:12px; color:#8b949e; }
.footer { margin-top:36px; color:#484f58; font-size:12px; }
.footer a { color:#58a6ff; text-decoration:none; }
"""


def _stat_cards(db):
    rows = analyse.summary(db)
    total = sum(r["indicators"] for r in rows)
    corr = len(analyse.corroborated(db))
    cards = [f'<div class="card hot"><div class="n">{total:,}</div>'
             f'<div class="l">Total indicators</div></div>']
    for r in rows:
        cards.append(f'<div class="card"><div class="n">{r["indicators"]:,}</div>'
                     f'<div class="l">{escape(r["type"])} indicators</div></div>')
    cards.append(f'<div class="card corr"><div class="n">{corr}</div>'
                 f'<div class="l">Multi-feed corroborated</div></div>')
    return "".join(cards)


def _table(rows, columns):
    head = "".join(f"<th>{escape(c)}</th>" for c in columns)
    body = []
    for r in rows:
        cells = []
        for c in columns:
            cls = ' class="type"' if c == "type" else (' class="feeds"' if c == "feeds" else "")
            cells.append(f"<td{cls}>{escape(str(r.get(c, '')))[:110]}</td>")
        body.append("<tr>" + "".join(cells) + "</tr>")
    return f"<table><tr>{head}</tr>{''.join(body)}</table>"


def _bars(items):
    if not items:
        return "<p class='sub'>No family data in current feeds.</p>"
    peak = max(i["count"] for i in items)
    rows = []
    for i in items:
        width = max(6, int(420 * i["count"] / peak))
        rows.append(f'<div class="bar-row"><div class="bar-label">{escape(i["name"])}</div>'
                    f'<div class="bar" style="width:{width}px"></div>'
                    f'<div class="bar-count">{i["count"]}</div></div>')
    return "".join(rows)


def render(db, generated_by="tfa"):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    feed_rows = analyse.feed_totals(db)
    corr_rows = analyse.corroborated(db)[:20]
    cves = analyse.recent(db, "cve", 10)
    families = analyse.top_context_terms(db, "ip") + analyse.top_context_terms(db, "url")

    html = f"""<!doctype html><html><head><meta charset="utf-8">
<title>Threat Feed Dashboard</title><style>{CSS}</style></head><body>
<h1>THREAT FEED <span>AGGREGATOR</span></h1>
<div class="sub">Generated {now} &middot; sources: {', '.join(escape(f['name']) for f in feed_rows)}</div>
<div class="grid">{_stat_cards(db)}</div>
<h2>Feed coverage</h2>
{_table(feed_rows, ["name", "description", "indicators"])}
<h2>Multi-feed corroborated indicators (highest confidence)</h2>
{_table(corr_rows, ["value", "type", "feed_count", "feeds"]) if corr_rows else "<p class='sub'>No cross-feed overlap in current dataset.</p>"}
<h2>Malware family / threat distribution</h2>
{_bars(sorted(families, key=lambda x: -x["count"])[:10])}
<h2>Latest known-exploited CVEs (CISA KEV)</h2>
{_table(cves, ["value", "first_seen", "context"])}
<div class="footer">Built with the <a href="#">threat-feed-aggregator</a> &middot; {escape(generated_by)}</div>
</body></html>"""
    return html


def save(db, path="output/dashboard.html", generated_by="tfa"):
    with open(path, "w") as f:
        f.write(render(db, generated_by))
    return path
