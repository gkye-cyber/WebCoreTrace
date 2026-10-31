import sys
import unittest
import json
from pathlib import Path
# adding src directory to sys.path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from web_core_trace.reporter import build_forensic_report, generate_json_report, generate_html_report
from web_core_trace.detector import ThreatMatch
from web_core_trace.parser import LogEntry

class TestReporter(unittest.TestCase):
    def test_build_forensic_report(self):
        entry_one = LogEntry(
            ip="198.51.100.10",
            timestamp=None,
            method="GET",
            raw_uri="/",
            decoded_uri="/",
            protocol="HTTP/1.1",
            status_code=200,
            response_size=100,
            referrer="-",
            user_agent="-",
            raw_line="sample access log line"
        )
        entry_two = LogEntry(
            ip="198.51.100.25",
            timestamp=None,
            method="GET",
            raw_uri="/",
            decoded_uri="/",
            protocol="HTTP/1.1",
            status_code=401,
            response_size=100,
            referrer="-",
            user_agent="-",
            raw_line="sample access log line"
        )
        match = ThreatMatch(
            category="SQLi",
            severity="High",
            description="SQL injection attempt",
            matched_payload="UNION SELECT",
            entry=entry_one,
            mitre_id="T1190"
        )
        report = build_forensic_report([entry_one, entry_two], [match])
        self.assertEqual(report.total_requests, 2)
        self.assertEqual(report.unique_ips, 2)
        self.assertEqual(report.status_code_distribution, {200: 1, 401:1})

    def test_generate_json_report(self):
        json_text = generate_json_report(build_forensic_report([], []))
        decoded = json.loads(json_text)
        self.assertEqual(decoded["total_requests"], 0)
        self.assertEqual(decoded["threats"], [])

    def test_generate_html_report(self):
        entry = LogEntry(
            ip="198.51.100.10",
            timestamp=None,
            method="GET",
            raw_uri="/test",
            decoded_uri="/test",
            protocol="HTTP/1.1",
            status_code=200,
            response_size=100,
            referrer="-",
            user_agent="-",
            raw_line="sample access log line"
        )
        match = ThreatMatch(
                    category="SQLi",
                    severity="High",
                    description="SQL injection attempt",
                    matched_payload="UNION SELECT",
                    entry=entry,
                    mitre_id="T1190"
                )
        html_text = generate_html_report(build_forensic_report([entry], [match]))
        self.assertIn("SQLi", html_text)
        self.assertIn("T1190", html_text)
        self.assertIn("UNION SELECT", html_text)

    def test_memory_threat_reporting_without_log_entry(self):
        mem_match = ThreatMatch(
            category="Executable Heap (RWX)",
            severity="Critical",
            description="Anomalous RWX memory region in php-fpm (PID 1234) at [heap].",
            matched_payload="0x7f000000-0x7f021000 rwxp [heap]",
            entry=None,
            mitre_id="T1055"
        )
        report = build_forensic_report(entries=[], threats=[mem_match])
        self.assertEqual(report.total_requests, 0)
        self.assertEqual(report.total_threats, 1)
        self.assertEqual(report.top_attacking_ips, [])
        self.assertEqual(report.category_distribution, {"Executable Heap (RWX)": 1})

        html_text = generate_html_report(report)
        self.assertIn("host-memory", html_text)
        self.assertIn("Executable Heap (RWX)", html_text)