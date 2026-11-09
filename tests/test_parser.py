import sys
import unittest
from pathlib import Path
# adding src directory to sys.path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from web_core_trace.parser import parse_log_line, parse_file

class TestParser(unittest.TestCase):
    # test parsing a single log line
    def test_parse_log_line(self):
        log_line = '127.0.0.1 - - [01/Jan/2023:00:00:00 +0000] "GET / HTTP/1.1" 200 1234 "-" "-"'
        result = parse_log_line(log_line)
        self.assertIsNotNone(result)
        self.assertEqual(result.ip, '127.0.0.1')
        self.assertEqual(result.method, 'GET')
        self.assertEqual(result.raw_uri, '/')
        self.assertEqual(result.protocol, 'HTTP/1.1')
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.response_size, 1234)
        self.assertEqual(result.referrer, '-')
        self.assertEqual(result.user_agent, '-')
        self.assertEqual(result.timestamp.year, 2023)

    # test url decoding of the URI
    def test_url_decoding(self):
        log_line = '203.0.113.45 - - [10/Oct/2026:13:56:01 -0400] "GET /products.php?id=1%20UNION%20SELECT HTTP/1.1" 200 4502 "-" "-"'
        result = parse_log_line(log_line)
        self.assertIsNotNone(result)
        self.assertEqual(result.raw_uri, '/products.php?id=1%20UNION%20SELECT')
        self.assertEqual(result.decoded_uri, '/products.php?id=1 UNION SELECT')

    # test log format variations (e.g., missing referrer and user agent)
    def test_log_format(self):
        log_line = '10.0.0.1 - - [10/Oct/2026:13:55:36 -0400] "GET /status HTTP/1.1" 200 42'
        result = parse_log_line(log_line)
        self.assertIsNotNone(result)
        self.assertEqual(result.referrer, '')
        self.assertEqual(result.user_agent, '')

    # test dash in response size field
    def test_dash_response_size(self):
        log_line = '10.0.0.1 - - [10/Oct/2026:13:55:36 -0400] "GET /style.css HTTP/1.1" 304 - "-" "-"'
        result = parse_log_line(log_line)
        self.assertIsNotNone(result)
        self.assertEqual(result.response_size, 0)  # dash should be treated as 0
        self.assertEqual(result.status_code, 304)

    # test malformed log line (should return None)
    def test_malformed_log_line(self):
        log_line = 'malformed log line'
        result = parse_log_line(log_line)
        self.assertIsNone(parse_log_line('malformed log line'))
        self.assertIsNone(parse_log_line('  \n')) # empty line should also return None
        self.assertIsNone(parse_log_line('INVALID LOG LINE WITHOUT PROPER FORMAT'))

    # test sample file parsing
    def test_parse_file(self):
        sample_file_path = Path(__file__).parent.parent / "sample_data" /"access_sample.log"
        entries = list(parse_file(sample_file_path))
        self.assertEqual(len(entries), 11)  # assuming sample_logs.txt has 8 valid log lines
        self.assertIsNotNone(entries[0])
