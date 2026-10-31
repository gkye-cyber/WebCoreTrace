import sys
import unittest
from pathlib import Path
# adding src directory to sys.path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from web_core_trace.parser import LogEntry
from web_core_trace.detector import (
    check_signatures, 
    detect_brute_force, 
    detect_php2shell_stale_worker, 
    ThreatDetector
)
from web_core_trace.memory_parser import (
    FunctionPointer,
    HeapChunk,
    MemoryRegion,
    MemorySnapshot,
    OpcacheScript,
    ProcessInfo
)


### helper function to create a LogEntry for testing
def make_entry(
        ip="192.168.1.1",
        method="GET",
        uri="/",
        status_code=200,
        user_agent="Mozilla/5.0",
        referrer="-"
) -> LogEntry:
    return LogEntry(
        ip=ip,
        timestamp=None,
        method=method,
        raw_uri=uri,
        decoded_uri=uri,
        protocol="HTTP/1.1",
        status_code=status_code,
        response_size=100,
        referrer=referrer,
        user_agent=user_agent,
        raw_line=""
    )

### signature and brute force detection tests
class TestDetector(unittest.TestCase):
    def test_benign_traffic(self):
        entry = make_entry(uri="/index.html", user_agent="Mozilla/5.0")
        matches = check_signatures(entry)
        self.assertEqual(len(matches), 0)  # no matches expected

    def test_sql_injection(self):
        entry = make_entry(uri="/products.php?id=1 UNION SELECT null, password FROM users")
        matches = check_signatures(entry)
        self.assertEqual(matches[0].mitre_id, "T1190")  # SQL Injection MITRE ID

    def test_lfi_detection(self):
        entry = make_entry(uri="/static/../../../../etc/passwd")
        matches = check_signatures(entry)
        self.assertTrue(any(m.category == "LFI" for m in matches))  # LFI category should be detected

    def test_rce_detection(self):
        entry = make_entry(uri="/cgi-bin/test.sh?cmd=whoami;id")
        matches = check_signatures(entry)
        self.assertTrue(any(m.category == "RCE" for m in matches)) # RCE category should be detected
        self.assertEqual(matches[0].mitre_tactic, "Execution")  # MITRE tactic for RCE

    def test_scanner_user_agent_detection(self):
        entry = make_entry(user_agent="sqlmap/1.6.0")
        matches = check_signatures(entry)
        self.assertTrue(any(m.category == "Scanner" for m in matches))  # Scanner category should be detected
        self.assertEqual(matches[0].mitre_tactic, "Reconnaissance")  # MITRE tactic for scanners

    def test_brute_force_below_threshold(self):
        entries = [make_entry(ip="10.0.0.1", status_code=404) for _ in range(2)] # generates a list of 2 entries
        matches = detect_brute_force(entries, threshold=3)
        self.assertEqual(len(matches), 0) # no matches expected

    def test_brute_force_at_or_above_threshold(self):
        entries = [make_entry(ip="10.0.0.1", status_code=404) for _ in range(3)] # generates a list of 3 entries
        matches = detect_brute_force(entries, threshold=3)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].category, "Brute Force")
        self.assertEqual(matches[0].entry.ip, "10.0.0.1")

    def test_php2shell_oom_detection(self):
        entry = make_entry(uri="/index.php?a[][][][][]=1")
        matches = check_signatures(entry)
        self.assertTrue(any(m.category == "PHP2Shell (CVE-2026-109618)" for m in matches))

    def test_php2shell_stale_state_detection(self):
        entry = make_entry(uri="/upload.php?PHP_SESSION_UPLOAD_PROGRESS=crash_state")
        matches = check_signatures(entry)
        self.assertTrue(any(m.category == "PHP2Shell (CVE-2026-109619)" for m in matches))

    def test_php2shell_stale_worker_sequence(self):
        entries = [
            make_entry(ip="10.0.0.5", uri="/worker.php", status_code=500),
            make_entry(ip="10.0.0.5", uri="/worker.php", status_code=200)
        ]
        matches = detect_php2shell_stale_worker(entries)
        self.assertTrue(any(m.category == "PHP2Shell (CVE-2026-109619)" for m in matches))

    # end-to-end test
    def test_threat_detector_end_to_end(self):
        entries = [
          make_entry(uri="/index.html", user_agent="Mozilla/5.0"), # benign
          make_entry(uri="/products.php?id=1 UNION SELECT null, password FROM users"), # sqli
          make_entry(ip="10.0.0.1", status_code=404, uri="/admin"),
          make_entry(ip="10.0.0.1", status_code=404, uri="/login"),
          make_entry(ip="10.0.0.1", status_code=404, uri="/.env") # brute force attempts
        ]
        detector = ThreatDetector()
        matches = detector.analyze(entries) 
        self.assertGreater(len(matches), 0)

    # memory heuristics test
    def test_analyze_memory_heuristics(self):
        snapshot = MemorySnapshot(
            source="test:memory",
            regions=[
                MemoryRegion(
                    start_addr=0x7F000000,
                    end_addr=0x7F021000,
                    permission="rwxp",
                    path="[heap]",
                    pid=1234,
                    process_name="php-fpm"
                )
            ],
            heap_chunks=[
                HeapChunk(
                    address=0x7F001000,
                    size=128,
                    is_freed=True,
                    target_ptr=0x7F002000,
                    owner_worker_pid=1234,
                    current_worker_pid=1235
                )
            ],
            function_pointers=[
                FunctionPointer(
                    symbol_name="zend_execute_ex",
                    target_addr=0xDEADBEEF,
                    valid_min_addr=0x55000000,
                    valid_max_addr=0x55100000,
                    pid=1234
                )
            ],
            opcache_scripts=[
                OpcacheScript(
                    script_path="eval()'d code",
                    memory_addr=0x7F005000,
                    exists_on_disk=False,
                    payload_preview="system('id');",
                    pid=1234
                )
            ],
            processes=[
                ProcessInfo(
                    pid=1300,
                    ppid=1234,
                    name="sh",
                    parent_name="php-fpm",
                    cmdline="/bin/sh -c id"
                )
            ]
        )

        detector = ThreatDetector()
        matches = detector.analyze_memory(snapshot)
        categories = {m.category for m in matches}

        self.assertIn("Memory UAF / Dangling Pointer", categories)
        self.assertIn("Orphan Zend Heap Structure", categories)
        self.assertIn("Executable Heap (RWX)", categories)
        self.assertIn("Function Pointer Hook / Corruption", categories)
        self.assertIn("Fileless Web Shell", categories)
        self.assertIn("Suspicious Worker Child Process", categories)