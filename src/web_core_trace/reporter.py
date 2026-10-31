from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Iterable, Optional
from pathlib import Path
from web_core_trace.parser import LogEntry
from web_core_trace.detector import ThreatMatch
from web_core_trace.enricher import IPEnrichment
import html
import json

@dataclass
class ForensicReport:
    total_requests: int
    unique_ips: int
    total_threats: int
    status_code_distribution: dict[int, int]
    top_attacking_ips: list[tuple[str, int]]
    top_targeted_uris: list[tuple[str, int]]
    category_distribution: dict[str, int]
    mitre_distribution: dict[str, int]
    threats: list[ThreatMatch] = field(default_factory=list)
    ip_enrichments: dict[str, IPEnrichment] = field(default_factory=dict)

### forensic report
def build_forensic_report(
        entries: Iterable[LogEntry],
        threats: list[ThreatMatch],
        ip_enrichments: Optional[dict[str, IPEnrichment]] = None
) -> ForensicReport:
    entry_list = list(entries)
    total_requests = len(entry_list)
    unique_ips = len({e.ip for e in entry_list})
    total_threats = len(threats)
    
    # calculation vars
    status_codes = dict(Counter(e.status_code for e in entry_list)) # status codes
    top_ips = Counter(t.entry.ip for t in threats if t.entry is not None).most_common(10) # top 10 IPs
    top_uris = Counter(t.entry.decoded_uri for t in threats if t.entry is not None).most_common(10) # top 10 URIs
    categories = dict(Counter(t.category for t in threats)) # mitre categories
    mitre_counts = dict(Counter(t.mitre_id for t in threats if t.mitre_id)) # mitre ids

    return ForensicReport(
        total_requests=total_requests,
        unique_ips=unique_ips,
        total_threats=total_threats,
        status_code_distribution=status_codes,
        top_attacking_ips=top_ips,
        top_targeted_uris=top_uris,
        category_distribution=categories,
        mitre_distribution=mitre_counts,
        threats=threats,
        ip_enrichments=ip_enrichments or {}
    )

### json export
def generate_json_report(
        report: ForensicReport,
        output_path: Optional[Path | str] = None,
        indent: int = 2
) -> str:
    # serialized helper for datetime; optional save to a file
    def _json_serializer(obj: Any) -> Any:
        if isinstance(obj, datetime):
            return obj.isoformat()
        return str(obj)

    report_dict = asdict(report)
    json_output = json.dumps(report_dict, indent=indent, default=_json_serializer)

    if output_path:
        Path(output_path).write_text(json_output, encoding="utf-8")

    return json_output

### html report generator
def generate_html_report(
        report: ForensicReport,
        output_path: Optional[Path | str] = None
) -> str:

    # render helper rows
    status_rows = "".join(
        f"<tr><td><code>{code}</code></td><td>{count}</td></tr>"
        for code, count in sorted(report.status_code_distribution.items())
    )

    # top attacking IPs with GeoIP enrichment
    ip_rows = ""
    for ip, count in report.top_attacking_ips:
        enrichment = report.ip_enrichments.get(ip)
        geo = f"{enrichment.country} ({enrichment.city})" if enrichment else "Unknown"
        org = enrichment.org if enrichment else "-"
        ip_rows += f"<tr><td><code>{html.escape(ip)}</code></td><td>{count}</td><td>{html.escape(geo)}</td><td>{html.escape(org)}</td></tr>"

    # category and MITRE breakdown
    category_rows = "".join(
        f"<tr><td><strong>{html.escape(cat)}</strong></td><td>{count}</td></tr>"
        for cat, count in sorted(report.category_distribution.items(), key=lambda x: x[1], reverse=True)
    )
    
    # detailed threat rows
    threat_rows = ""
    for t in report.threats:
        if t.entry is not None:
            ts = t.entry.timestamp.strftime("%Y-%m-%d %H:%M:%S") if t.entry.timestamp else "-"
            ip_val = t.entry.ip
            uri_val = t.entry.decoded_uri[:80]
        else:
            ts = "-"
            ip_val = "host-memory"
            uri_val = t.description[:80]

        severity_class = t.severity.lower().replace(" ", "-")
        threat_rows += f"""
        <tr>
            <td>{html.escape(ts)}</td>
            <td><code>{html.escape(ip_val)}</code></td>
            <td><span class="badge badge-{severity_class}">{html.escape(t.severity)}</span></td>
            <td>{html.escape(t.category)}</td>
            <td><code>{html.escape(t.mitre_id or '-')}</code></td>
            <td><code>{html.escape(t.matched_payload[:60])}</code></td>
            <td class="uri-col"><code>{html.escape(uri_val)}</code></td>
        </tr>
        """

    # html tmeplate and styling
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Web Core Trace Forensic Report</title>
<style>
    :root {{
        --bg-primary: #0f172a;
        --bg-secondary: #1e293b;
        --bg-card: #334155;
        --text-primary: #f8fafc;
        --text-secondary: #94a3b8;
        --accent: #38bdf8;
        --border: #475569;
        --critical: #ef4444;
        --high: #f97316;
        --medium: #eab308;
        --low: #22c55e;
    }}
    body {{
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        background-color: var(--bg-primary);
        color: var(--text-primary);
        margin: 0;
        padding: 2rem;
    }}
    .container {{ max-width: 1300px; margin: 0 auto; }}
    header {{ margin-bottom: 2rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem; }}
    h1 {{ margin: 0 0 0.5rem 0; font-size: 2rem; color: var(--accent); }}
    .subtitle {{ color: var(--text-secondary); margin: 0; font-size: 0.95rem; }}
    .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
    .kpi-card {{ background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; }}
    .kpi-title {{ font-size: 0.85rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.05em; }}
    .kpi-value {{ font-size: 2.25rem; font-weight: bold; margin-top: 0.5rem; }}
    .tables-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 2rem; }}
    @media (max-width: 900px) {{ .tables-grid {{ grid-template-columns: 1fr; }} }}
    .section-card {{ background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; margin-bottom: 2rem; }}
    .section-card h2 {{ margin-top: 0; font-size: 1.2rem; color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; text-align: left; }}
    th, td {{ padding: 0.75rem 0.5rem; border-bottom: 1px solid var(--border); }}
    th {{ color: var(--text-secondary); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; }}
    code {{ background: rgba(0,0,0,0.3); padding: 0.2rem 0.4rem; border-radius: 4px; font-family: monospace; font-size: 0.85rem; }}
    .badge {{ padding: 0.2rem 0.6rem; border-radius: 4px; font-weight: bold; font-size: 0.75rem; text-transform: uppercase; }}
    .badge-critical {{ background: var(--critical); color: #fff; }}
    .badge-high {{ background: var(--high); color: #fff; }}
    .badge-medium {{ background: var(--medium); color: #000; }}
    .badge-low {{ background: var(--low); color: #000; }}
    .uri-col {{ max-width: 300px; word-break: break-all; }}
</style>
</head>
<body>
<div class="container">
    <header>
        <h1> Web Core Trace Forensic Report</h1>
        <p class="subtitle">Automated Threat Hunter Incident Analysis</p>
    </header>

    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-title">Total Requests</div>
            <div class="kpi-value">{report.total_requests}</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">Unique IPs</div>
            <div class="kpi-value">{report.unique_ips}</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">Total Threats Detected</div>
            <div class="kpi-value" style="color: var(--critical);">{report.total_threats}</div>
        </div>
    </div>

    <div class="tables-grid">
        <div class="section-card">
            <h2>Top Attacking IPs & Geolocation</h2>
            <table>
                <thead><tr><th>IP Address</th><th>Alerts</th><th>Location</th><th>ISP / Org</th></tr></thead>
                <tbody>{ip_rows or "<tr><td colspan='4'>No attacking IPs identified</td></tr>"}</tbody>
            </table>
        </div>

        <div class="section-card">
            <h2>Threat Categories</h2>
            <table>
                <thead><tr><th>Category</th><th>Count</th></tr></thead>
                <tbody>{category_rows or "<tr><td colspan='2'>No threats identified</td></tr>"}</tbody>
            </table>
        </div>
    </div>

    <div class="section-card">
        <h2>Detailed Security Incidents</h2>
        <table>
            <thead>
                <tr><th>Timestamp</th><th>IP</th><th>Severity</th><th>Category</th><th>MITRE</th><th>Matched Payload</th><th>Request URI</th></tr>
            </thead>
            <tbody>{threat_rows or "<tr><td colspan='7'>No incident records found. Clean traffic.</td></tr>"}</tbody>
        </table>
    </div>
</div>
</body>
</html>
"""

    if output_path:
        Path(output_path).write_text(html_content, encoding="utf-8")

    return html_content