"""Automated Web Server Access Log Threat Hunter & Forensic Triage Tool."""

__version__ = "1.1.0"

from web_core_trace.parser import LogEntry, parse_log_line, parse_file
from web_core_trace.detector import ThreatDetector, ThreatMatch, SignatureRule
from web_core_trace.enricher import IPEnricher, IPEnrichment, enrich_ips
from web_core_trace.reporter import (
    ForensicReport,
    build_forensic_report,
    generate_json_report,
    generate_html_report,
)

__all__ = [
    "__version__",
    "LogEntry",
    "parse_log_line",
    "parse_file",
    "ThreatDetector",
    "ThreatMatch",
    "SignatureRule",
    "IPEnricher",
    "IPEnrichment",
    "enrich_ips",
    "ForensicReport",
    "build_forensic_report",
    "generate_json_report",
    "generate_html_report",
]