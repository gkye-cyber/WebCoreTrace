import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from web_core_trace.memory_parser import (
    acquire_and_scan,
    inspect_live_host,
    parse_memory_dump
)

class TestMemoryParser(unittest.TestCase):

    # testing structure json dump ingestion
    def test_parse_json_memory_dump(self):
        sample_data = {
            "regions": [
                {
                    "start_addr": 0x7F000000,
                    "end_addr": 0x7F021000,
                    "permission": "rwxp",
                    "path": "[heap]",
                    "pid": 1234,
                    "process_name": "php-fpm"
                }
            ],
            "heap_chunks": [
                {
                    "address": 0x7F001000,
                    "size": 256,
                    "is_freed": True,
                    "target_ptr": 0x7F002000,
                    "owner_worker_pid": 1234,
                    "current_worker_pid": 1235
                }
            ],
            "function_pointers": [
                {
                    "symbol_name": "zend_execute_ex",
                    "target_addr": 0xDEADBEEF,
                    "valid_min_addr": 0x55000000,
                    "valid_max_addr": 0x55100000,
                    "pid": 1234
                }
            ],
            "opcache_scripts": [
                {
                    "script_path": "eval()'d code",
                    "memory_addr": 0x7F005000,
                    "exists_on_disk": False,
                    "payload_preview": "system($_GET['cmd']);",
                    "pid": 1234
                }
            ],
            "processes": [
                {
                    "pid": 1300,
                    "ppid": 1234,
                    "name": "sh",
                    "parent_name": "php-fpm",
                    "cmdline": "/bin/sh -c id"
                }
            ]
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            dump_path = Path(tmp_dir) / "vol3_snapshot.json"
            dump_path.write_text(json.dumps(sample_data), encoding="utf-8")

            snapshot = parse_memory_dump(dump_path)
            self.assertEqual(snapshot.source, "dump:vol3_snapshot.json")
            self.assertEqual(len(snapshot.regions), 1)
            self.assertEqual(snapshot.regions[0].permission, "rwxp")
            self.assertEqual(len(snapshot.heap_chunks), 1)
            self.assertTrue(snapshot.heap_chunks[0].is_freed)
            self.assertEqual(len(snapshot.function_pointers), 1)
            self.assertEqual(snapshot.function_pointers[0].symbol_name, "zend_execute_ex")
            self.assertEqual(len(snapshot.opcache_scripts), 1)
            self.assertFalse(snapshot.opcache_scripts[0].exists_on_disk)
            self.assertEqual(len(snapshot.processes), 1)
            self.assertEqual(snapshot.processes[0].name, "sh")

    # testing parse operation of raw binary file
    def test_parse_binary_memory_dump_mmap(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            raw_path = Path(tmp_dir) / "core.raw"
            raw_bytes = b"\x00" * 64 + b"eval()'d code\x00" + b"/bin/sh\x00" + b"rwxp\x00"
            raw_path.write_bytes(raw_bytes)

            snapshot = parse_memory_dump(raw_path)
            self.assertEqual(snapshot.source, "dump:core.raw")
            self.assertTrue(any(sig.startswith("fileless_eval_stream@") for sig in snapshot.raw_signatures))
            self.assertTrue(any(sig.startswith("spawned_shell_string@") for sig in snapshot.raw_signatures))
            self.assertTrue(any(sig.startswith("rwx_memory_mapping@") for sig in snapshot.raw_signatures))
            self.assertEqual(len(snapshot.opcache_scripts), 1)
            self.assertEqual(snapshot.opcache_scripts[0].script_path, "eval()'d code")
            self.assertFalse(snapshot.opcache_scripts[0].exists_on_disk)

    # testing live host inspection
    def test_inspect_live_host_mock_proc(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            proc_root = Path(tmp_dir)

            # parent process
            pid_1000 = proc_root / "1000"
            pid_1000.mkdir()
            (pid_1000 / "comm").write_text("php-fpm\n", encoding="utf-8")
            (pid_1000 / "cmdline").write_bytes(b"php-fpm: pool www\x00")
            (pid_1000 / "status").write_text("Name:\tphp-fpm\nPPid:\t1\n", encoding="utf-8")
            (pid_1000 / "maps").write_text(
                "7f000000-7f021000 rwxp 00000000 00:00 0          [heap]\n",
                encoding="utf-8",
            )

            # child process
            pid_1001 = proc_root / "1001"
            pid_1001.mkdir()
            (pid_1001 / "comm").write_text("sh\n", encoding="utf-8")
            (pid_1001 / "cmdline").write_bytes(b"/bin/sh\x00-c\x00whoami\x00")
            (pid_1001 / "status").write_text("Name:\tsh\nPPid:\t1000\n", encoding="utf-8")

            snapshot = inspect_live_host(proc_root=proc_root)
            self.assertEqual(len(snapshot.processes), 2)
            self.assertEqual(len(snapshot.regions), 1)
            self.assertEqual(snapshot.regions[0].permission, "rwxp")
            self.assertEqual(snapshot.regions[0].path, "[heap]")

            child_proc = next(p for p in snapshot.processes if p.pid == 1001)
            self.assertEqual(child_proc.name, "sh")
            self.assertEqual(child_proc.parent_name, "php-fpm")
            self.assertEqual(child_proc.cmdline, "/bin/sh -c whoami")

    # test acquisition automation and error handling
    def test_acquire_and_scan(self):
        with self.assertRaises(ValueError):
            acquire_and_scan(tool="unsupported_tool")

        def fake_avml_run(cmd, **kwargs):
            # cmd: ["avml", "<tmp_dir>/acquired_memory.raw"]
            Path(cmd[1]).write_bytes(b"\x00" * 16 + b"eval()'d code\x00")

        with patch("subprocess.run", side_effect=fake_avml_run) as mock_run:
            snapshot = acquire_and_scan(tool="avml")
            mock_run.assert_called_once()
            self.assertEqual(snapshot.source, "acquired:avml")
            self.assertEqual(len(snapshot.opcache_scripts), 1)

if __name__ == "__main__":
    unittest.main()