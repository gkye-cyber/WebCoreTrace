from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import json
import mmap
import os
import subprocess
import tempfile

@dataclass
class MemoryRegion:
    start_addr: int
    end_addr: int
    permission: str # eg: 'r-xp', 'rw-p', rwxp'
    path: str       # eg: '[heap]', '[stack]', '[anon:zend_alloc]'
    pid: int = 0
    process_name: str = "php-fpm"

@dataclass
class HeapChunk:
    address: int
    size: int
    is_freed: bool
    target_ptr: int = 0
    owner_worker_pid: int = 0
    current_worker_pid: int = 0

@dataclass
class FunctionPointer:
    symbol_name: str  # eg: 'zend_execute_ex', 'zend_stream_open'
    target_addr: int
    valid_min_addr: int
    valid_max_addr: int
    pid: int = 0

@dataclass
class OpcacheScript:
    script_path: str  # eg: "/var/www/index.php" or "eval()'d code"
    memory_addr: int
    exists_on_disk: bool
    payload_preview: str = ""
    pid: int = 0

@dataclass
class ProcessInfo:
    pid: int
    ppid: int
    name: str          # eg: 'sh', 'bash', 'cmd.exe'
    parent_name: str   # eg: 'php-fpm', 'httpd', 'nginx'
    cmdline: str = ""
    user: str = ""     # eg: 'www-data', 'apache', 'nobody'

@dataclass
class NetworkConnection:
    remote_ip: str
    remote_port: int
    local_port: int = 0
    protocol: str = "tcp"
    pid: int = 0
    process_name: str = "php-fpm"
    state: str = "ESTABLISHED"

@dataclass
class MemorySnapshot:
    source: str
    regions: list[MemoryRegion] = field(default_factory=list)
    heap_chunks: list[HeapChunk] = field(default_factory=list)
    function_pointers: list[FunctionPointer] = field(default_factory=list)
    opcache_scripts: list[OpcacheScript] = field(default_factory=list)
    processes: list[ProcessInfo] = field(default_factory=list)
    network_connections: list[NetworkConnection] = field(default_factory=list)
    raw_signatures: list[str] = field(default_factory=list)

### static core / RAM dump ingestion (--memory-dump)
def parse_memory_dump(dump_path: Path | str) -> MemorySnapshot:
    path = Path(dump_path)
    if not path.is_file():
        raise FileNotFoundError(f"Memory dump not found: {path}")

    snapshot = MemorySnapshot(source=f"dump:{path.name}")

    # 1. If structured JSON snapshot (eg: Volatiility 3 export or test fixture)
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        snapshot.regions = [MemoryRegion(**r) for r in data.get("regions", [])]
        snapshot.heap_chunks = [HeapChunk(**c) for c in data.get("heap_chunks", [])]
        snapshot.function_pointers = [FunctionPointer(**fp) for fp in data.get("function_pointers", [])]
        snapshot.opcache_scripts = [OpcacheScript(**s) for s in data.get("opcache_scripts", [])]
        snapshot.processes = [ProcessInfo(**p) for p in data.get("processes", [])]
        snapshot.network_connections = [NetworkConnection(**nc) for nc in data.get("network_connections", [])]
        snapshot.raw_signatures = data.get("raw_signatures", [])
        return snapshot

    # 2. Binary RAM / ELF Core Dump via zero-copy mmap slicing
    file_size = path.stat().st_size
    if file_size == 0:
        return snapshot

    with path.open("rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            # scanning image for known memory-resident markers
            markers = {
                b"eval()'d code": "fileless_eval_stream",
                b"/bin/sh": "spawned_shell_string",
                b"rwxp": "rwx_memory_mapping",
                b"_zend_mm_heap": "zend_heap_structure",
                b"/wp-content/upgrade/": "wp_upgrade_staging_path",
                b"setup-config.php": "wp_staged_installer"
            }
            for pattern, label in markers.items():
                pos = mm.find(pattern)
                if pos != -1:
                    snapshot.raw_signatures.append(f"{label}@0x{pos:x}")

            # if marker is found in binary, synthesize OpcacheScript artifact
            eval_pos = mm.find(b"eval()'d code")
            if eval_pos != -1:
                snapshot.opcache_scripts.append(
                    OpcacheScript(
                        script_path="eval()'d code",
                        memory_addr=eval_pos,
                        exists_on_disk=False,
                        payload_preview="Binary mmap match: eval()'d code"
                    )
                )

    return snapshot

### Live Target Host Inspection (--live-host)
def inspect_live_host(pids: Optional[list[int]] = None, proc_root: Path | str = "/proc") -> MemorySnapshot:
    proc_path = Path(proc_root)
    snapshot = MemorySnapshot(source=f"live:{proc_path}")

    if not proc_path.exists():
        return snapshot

    # discover numeric PID directories if pids not specified
    if pids is None:
        pids = [int(p.name) for p in proc_path.iterdir() if p.is_dir() and p.name.isdigit()]

    for pid in pids:
        pid_dir = proc_path / str(pid)
        if not pid_dir.exists():
            continue

        try:
            comm_file = pid_dir / "comm"
            proc_name = comm_file.read_text(encoding="utf-8", errors="replace").strip() if comm_file.exists() else ""

            cmdline_file = pid_dir / "cmdline"
            cmdline = cmdline_file.read_bytes().replace (b"\x00", b" ").decode("utf-8", errors="replace").strip() if cmdline_file.exists() else ""

            # parsing /proc/[pid]/status for PPID
            ppid = 0
            status_file = pid_dir / "status"
            if status_file.exists():
                for line in status_file.read_text(encoding="utf-8", errors="replace").splitlines():
                    if line.startswith("PPid:"):
                        ppid = int(line.split(":", 1)[1].strip())
                        break

            parent_comm_file = proc_path / str(ppid) / "comm"
            parent_name = parent_comm_file.read_text(encoding="utf-8", errors="replace").strip() if parent_comm_file.exists() else "unknown"

            snapshot.processes.append(
                ProcessInfo(pid=pid, ppid=ppid, name=proc_name, parent_name=parent_name, cmdline=cmdline)
            )

            # parsing /proc/[pid]/maps for memory regions
            maps_file = pid_dir / "maps"
            if maps_file.exists():
                for line in maps_file.read_text(encoding="utf-8", errors="replace").splitlines():
                    parts = line.split(maxsplit=5)
                    if len(parts) >= 2:
                        addr_range, perms = parts[0], parts[1]
                        region_path = parts[5].strip() if len(parts) == 6 else "[anon]"
                        start_s, end_s = addr_range.split("-", 1)
                        snapshot.regions.append(
                            MemoryRegion(
                                start_addr=int(start_s, 16),
                                end_addr=int(end_s, 16),
                                permission=perms,
                                path=region_path,
                                pid=pid,
                                process_name=proc_name
                            )
                        )

            # parsing /proc/[pid]/net/tcp for active outbound sockets
            tcp_file = pid_dir / "net" / "tcp"
            if tcp_file.exists():
                for line in tcp_file.read_text(encoding="utf-8", errors="replace").splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4:
                        local_hex, rem_hex, state_hex = parts[1], parts[2], parts[3]
                        if ":" in rem_hex and ":" in local_hex:
                            rem_ip_h, rem_port_h = rem_hex.split(":", 1)
                            _, loc_port_h = local_hex.split(":", 1)
                            rem_port = int(rem_port_h, 16)
                            loc_port = int(loc_port_h, 16)
                            if rem_port > 0 and len(rem_ip_h) == 8:
                                ip_int = int(rem_ip_h, 16)
                                octets = [str((ip_int >> (8 * i)) & 0xFF) for i in range(4)]
                                rem_ip = ".".join(octets)
                                state = "ESTABLISHED" if state_hex == "01" else state_hex
                                snapshot.network_connections.append(
                                    NetworkConnection(
                                        remote_ip=rem_ip,
                                        remote_port=rem_port,
                                        local_port=loc_port,
                                        protocol="tcp",
                                        pid=pid,
                                        process_name=proc_name,
                                        state=state
                                    )
                                )

        except (PermissionError, OSError, ValueError):
            continue

    return snapshot

### automated memory acquisition and scan (--acquire-and-scan)
def acquire_and_scan(tool: str = "avml", target_pid: Optional[int] = None) -> MemorySnapshot:
    with tempfile.TemporaryDirectory() as tmp_dir:
        dump_file = Path(tmp_dir) / "acquired_memory.raw"

        if tool == "avml":
            cmd = ["avml", str(dump_file)]
        elif tool == "gcore" and target_pid is not None:
            cmd = ["gcore", "-o", str(dump_file), str(target_pid)]
        else:
            raise ValueError(f"Unsupported acquisition configuration: tool={tool}, pid={target_pid}")

        subprocess.run(cmd, check=True, capture_output=True, text=True)

        # handles gcore naming convention
        actual_file = dump_file if dump_file.exists() else Path(f"{dump_file}.{target_pid}")
        snapshot = parse_memory_dump(actual_file)
        snapshot.source = f"acquired:{tool}"
        return snapshot