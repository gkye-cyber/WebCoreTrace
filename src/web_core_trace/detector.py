from dataclasses import dataclass
from collections import defaultdict
from typing import Iterable, Optional
from web_core_trace.memory_parser import MemorySnapshot
from web_core_trace.parser import LogEntry
import re

@dataclass
class ThreatMatch:
    category: str
    severity: str
    description: str
    matched_payload: str
    entry: Optional[LogEntry] = None
    mitre_id: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None

@dataclass
class SignatureRule:
    name: str
    category: str
    severity: str
    description: str
    pattern: re.Pattern
    target_field: str="decoded_uri"  # default target field is decoded_uri
    mitre_id: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None

### signature rules for various types of attacks
# SQLi signature rule
sqlli_rule = SignatureRule(
    name="SQL Injection",
    category="SQLi",
    severity="High",
    description="Detects SQL injection attempts in the URI.",
    pattern=re.compile(
    r"(?i)(\bUNION\b\s+(?:ALL\s+)?\bSELECT\b|"
    r"\bSELECT\b\s+.*\bFROM\b|"
    r"\bINSERT\b\s+INTO\b|"
    r"\bDROP\b\s+(?:TABLE|DATABASE)\b|"
    r"'\s*OR\s+['\d\w]+=['\d\w]+|"
    r"--\s*|/\*|\*/|"
    r"@@version|CHAR\(|CONVERT\()"
    ),
    target_field="decoded_uri",
    mitre_id="T1190",
    mitre_technique="Exploit Public-Facing Application",
    mitre_tactic="Initial Access"
)

# local file inclusion/path trversal signature rule
lfi_rule = SignatureRule(
    name="Local File Inclusion",
    category="LFI",
    severity="High",
    description="Detects local file inclusion or path traversal attempts in the URI.",
    pattern=re.compile(r"(?i)(\.\./|\.\.\\|/etc/passwd|/proc/self/environ|/var/www/html|/boot.ini)"),
    target_field="decoded_uri",
    mitre_id="T1190",
    mitre_technique="Exploit Public-Facing Application",
    mitre_tactic="Initial Access"
)

# remote code execution signature rule
rce_rule = SignatureRule(
    name="Remote Code Execution",
    category="RCE",
    severity="Critical",
    description="Detects remote code execution attempts in the URI.",
    pattern=re.compile(r"(?i)(\bexec\b|\bsystem\b|\bpopen\b|\bpassthru\b|\beval\b|\bwhoami\b|\bid\b\s*;|;\s*\bid\b|\bcat\s+/etc/|\bphpinfo\b)"),
    target_field="decoded_uri",
    mitre_id="T1059.004",
    mitre_technique="Command and Scripting Interpreter: Unix Shell",
    mitre_tactic="Execution"
)

# malicious scanner user agent signature rule
scanner_rule = SignatureRule(
    name="Malicious Scanner",
    category="Scanner",
    severity="Medium",
    description="Detects known malicious scanner user agents.",
    pattern=re.compile(r"(?i)\b(nmap|nikto|sqlmap|acunetix|nessus|openvas|fimap|dirbuster|gobuster|ffuf|wfuzz)\b"),
    target_field="user_agent",
    mitre_id="T1595.002",
    mitre_technique="Active Scanning: Vulnerability Scanning",
    mitre_tactic="Reconnaissance"
)

# sensitive file access signature rule
sensitive_file_rule = SignatureRule(
    name="Sensitive File Access",
    category="Sensitive File Access",
    severity="High",
    description="Detects attempts to access sensitive files.",
    pattern=re.compile(r"(?i)(/\.env|/\.git|/etc/passwd|/etc/shadow|/proc/self/environ|/boot\.ini|win\.ini|wp-config\.php)"),
    target_field="decoded_uri",
    mitre_id="T1552.001",
    mitre_technique="Unsecured Credentials: Credentials in Files",
    mitre_tactic="Credential Access"
)

# XSS signature rule
xss_rule = SignatureRule(
    name="Cross-Site Scripting",
    category="XSS",
    severity="High",
    description="Detects cross-site scripting attempts in the URI.",
    pattern=re.compile(r"(?i)(<script\b>|</script>|javascript:|onerror\s*=|onload\s*=|alert\(|prompt\(|confirm\()"),
    target_field="decoded_uri",
    mitre_id="T1059.007",
    mitre_technique="Command and Scripting Interpreter: JavaScript",
    mitre_tactic="Execution"
)

# cloud metadata probing signature rule
cloud_metadata_rule = SignatureRule(
    name="Cloud Metadata Probing",
    category="Cloud Metadata Probing",
    severity="Critical",
    description="Detects attempts to access cloud metadata.",
    pattern=re.compile(r"(?i)(169\.254\.169\.254|/latest/meta-data/?)"),
    target_field="decoded_uri",
    mitre_id="T1552.005",
    mitre_technique="Unsecured Credentials: Cloud Instance Metadata API",
    mitre_tactic="Credential Access"
)

# php2shell OOM state cleanup signature rule
php2shell_oom_rule = SignatureRule(
    name="php2shell OOM State Trigger",
    category="PHP2Shell (CVE-2026-109618)",
    severity="Critical",
    description="Detects oversized URL-encoded keys/queries or deep array nesting designed to trigger OOM state cleanup.",
    pattern=re.compile(
        r"(?i)(?:\[\s*\]\s*){5,}|"
        r"[?&][^=&\s]{128,}=|"
        r"[?&][^=&\s]+=[^&\s]{256,}|"
        r"(?:%[0-9a-f]{2}){64,}"
    ),
    target_field="raw_uri", # catches raw '%XX' floods as well as long key/values
    mitre_id="T1190",
    mitre_technique="Exploit Public-Facing Application",
    mitre_tactic="Initial Access"
)

# php2shell multiplart and stale-state manipulation rule
php2shell_stale_state_rule = SignatureRule(
    name="PHP2Shell Stale-State Manipulation",
    category="PHP2Shell (CVE-2026-109619)",
    severity="Critical",
    description="Detects multipart anomalies and stale-state manipulation targeting persistent worker threads.",
    pattern=re.compile(
        r"(?i)(PHP_SESSION_UPLOAD_PROGRESS|multipart/form-data|boundary=|"
        r"_zend_mm_|auto_prepend_file|allow_url_include)"
    ),
    target_field="decoded_uri",
    mitre_id="T1190",
    mitre_technique="Exploit Public-Facing Application",
    mitre_tactic="Initial Access"
)

# WordPress CVE-2026-119977 upgrade staging race and installer hijack rule
wp_upgrade_staging_rule = SignatureRule(
    name="WordPress Upgrade Staging Exploit",
    category="WordPress Upgrade Race (CVE-2026-119977)",
    severity="Critical",
    description="Detects direct requests for setup-config.phpp, install.php, or residual PHP scripts under /wp-content/upgrade/.",
    pattern=re.compile(
        r"(?i)/wp-content/upgrade/[^/\s]+/(?:(?:setup-config|install)\.php(?:\?step=\d+)?|[^\s?]*\.php)"
    ),
    target_field="decoded_uri",
    mitre_id="T1190",
    mitre_technique="Exploit Public-Facing Application",
    mitre_tactic="Initial Access"
    )

### matching function to check log entry against signature rules
RULES: list[SignatureRule] = [
    sqlli_rule,
    lfi_rule,
    rce_rule,
    scanner_rule,
    sensitive_file_rule,
    xss_rule,
    cloud_metadata_rule,
    php2shell_oom_rule,
    php2shell_stale_state_rule,
    wp_upgrade_staging_rule
]

def check_signatures(entry: LogEntry, rules: Optional[list[SignatureRule]] = None) -> list[ThreatMatch]:
    if rules is None:
        rules = RULES
    matches: list[ThreatMatch] = []
    for rule in rules:
        # dynamically get the target field from the log entry
        target_value = getattr(entry, rule.target_field, "")
        match = rule.pattern.search(target_value)
        if match:
            matches.append(
                ThreatMatch(
                    category=rule.category,
                    severity=rule.severity,
                    description=rule.description,
                    matched_payload=match.group(0),
                    entry=entry,
                    mitre_id=rule.mitre_id,
                    mitre_technique=rule.mitre_technique,
                    mitre_tactic=rule.mitre_tactic
                )
            )
    return matches

### brute force detection based on failed login attempts
def detect_brute_force(
        entries: Iterable[LogEntry],
        threshold: int = 3,
        status_codes: tuple[int] = (401, 403, 404)
) -> list[ThreatMatch]:
    failed_requests_by_ip = defaultdict(list)
    for entry in entries:
        if entry.status_code in status_codes:
            failed_requests_by_ip[entry.ip].append(entry)

    matches: list[ThreatMatch] = []
    for ip, failed_list in failed_requests_by_ip.items():
        if len(failed_list) >= threshold:
            matches.append(
                ThreatMatch(
                    category="Brute Force",
                    severity="High",
                    description=f"Detected {len(failed_list)} failed requests from IP {ip}.",
                    matched_payload=f"Potential directory brute-force: {len(failed_list)} | Sample targets: {','.join(e.decoded_uri for e in failed_list[:3])}",
                    entry=failed_list[-1], # use the last entry as a representative sample
                    mitre_id="T1595.003",
                    mitre_technique="Active Scanning: Wordlist Scanning",
                    mitre_tactic="Reconnaissance"
                    )
                )
    return matches

### behavioral detection for PHP2Shell persistent worker stale-state abuse
def detect_php2shell_stale_worker(entries: Iterable[LogEntry]) -> list[ThreatMatch]:
    entries_by_ip = defaultdict(list)
    for entry in entries:
        entries_by_ip[entry.ip].append(entry)

    matches: list[ThreatMatch] = []
    for ip, ip_entries in entries_by_ip.items():
        for i in range(len(ip_entries) - 1):
            curr_entry = ip_entries[i]
            next_entry = ip_entries[i + 1]
            """
            checking for 505/502/503 worker fault on PHP route followed by
            an immediate follow-up
            """
            if (
                curr_entry.status_code in (500, 502, 503)
                and ".php" in curr_entry.decoded_uri.lower()
                and next_entry.status_code == 200
            ):
                matches.append(
                    ThreatMatch(
                        category="PHP2Shell (CVE-2026-109619)",
                        severity="Critical",
                        description=f"Detected worker fault ({curr_entry.status_code}) followed by immediate state-reuse request from {ip}.",
                        matched_payload=f"Fault: {curr_entry.method} {curr_entry.decoded_uri[:40]} ({curr_entry.status_code}) -> Reuse: {next_entry.method} {next_entry.decoded_uri[:40]} ({next_entry.status_code})",
                        entry=next_entry,
                        mitre_id="T1190",
                        mitre_technique="Exploit Public-Facing Application",
                        mitre_tactic="Initial Access"
                    )
                )
                break
    return matches

### behavioral detection for WordPress CVE-2026-119977 upgrade race polling & staged install POST
def detect_wp_upgrade_race(entries: Iterable[LogEntry], threshold: int = 3) -> list[ThreatMatch]:
    upgrade_requests_by_ip = defaultdict(list)
    matches: list[ThreatMatch] = []

    for entry in entries:
        uri_lower = entry.decoded_uri.lower()
        if "/wp-content/upgrade/" in  uri_lower:
            upgrade_requests_by_ip[entry.ip].append(entry)
            if entry.method.upper() == "POST" and ("setup-config.php" in uri_lower or "install.php" in uri_lower):
                matches.append(
                    ThreatMatch(
                        category="WordPress Upgrade Race (CVE-2026-119977)",
                        severity="Critical",
                        description=f"Detected staged installer POST submission ({entry.decoded_uri}) from {entry.ip}.",
                        matched_payload=f"{entry.method} {entry.decoded_uri} ({entry.status_code})",
                        entry=entry,
                        mitre_id="T1190",
                        mitre_technique="Exploit Public-Facing Application",
                        mitre_tactic="Initial Access"
                    )
                )
    for ip, req_list in upgrade_requests_by_ip.items():
        if len(req_list) >= threshold:
                sample_paths = ",".join(e.decoded_uri for e in req_list[:3])
                matches.append(
                    ThreatMatch(
                        category="WordPress Upgrade Probing (CVE-2026-119977)",
                        severity="High",
                        description=f"Detected high-frequency polling ({len(req_list)} requests) targeting /wp-content/upgrade/ staging paths from {ip}",
                        matched_payload=f"Upgrade race polling: {len(req_list)} requests | Samples: {sample_paths}",
                        entry=req_list[-1],
                        mitre_id="T1595.003",
                        mitre_technique="Active Scanning: Wordlist Scanning",
                        mitre_tactic="Reconnaissance"
                )
            )
    return matches

### memory layer heuristics (core mode)
def detect_heap_anomalies(snapshot: MemorySnapshot) -> list[ThreatMatch]:
    matches: list[ThreatMatch] = []
    for chunk in snapshot.heap_chunks:
        if chunk.is_freed and chunk.target_ptr != 0:
            matches.append(
                ThreatMatch(
                    category="Memory UAF / Dangling Pointer",
                    severity="Critical",
                    description=f"Freed Zend heap chunk at 0x{chunk.address:x} retains active target pointer 0x{chunk.target_ptr:x}.",
                    matched_payload=f"chunk=0x{chunk.address:x} size={chunk.size} target_ptr=0x{chunk.target_ptr:x}",
                    mitre_id="T1068",
                    mitre_technique="Exploitation for Privilege Escalation",
                    mitre_tactic="Privilege Escalation"
                )
            )
        if (
            chunk.owner_worker_pid != 0 
            and chunk.current_worker_pid != 0 
            and  chunk.owner_worker_pid!= chunk.current_worker_pid
        ):
            matches.append(
                ThreatMatch(
                    category="Orphan Zend Heap Structure",
                    severity="High",
                    description=f"Heap chunk at 0x{chunk.address:x} crossed worker boundary (owner PID {chunk.owner_worker_pid} -> current PID {chunk.current_worker_pid}).",
                    matched_payload=f"chunk=0x{chunk.address:x} owner_pid={chunk.owner_worker_pid} current_pid={chunk.current_worker_pid}",
                    mitre_id="T1055",
                    mitre_technique="Process Injection",
                    mitre_tactic="Defense Evasion"
                )
            )
    return matches

### detecting executable heaps
def detect_rwx_regions(snapshot: MemorySnapshot) -> list[ThreatMatch]:
    matches: list[ThreatMatch] = []
    for region in snapshot.regions:
        if "rwx" in region.permission.lower():
            matches.append(
                ThreatMatch(
                    category="Executable Heap (RWX)",
                    severity="Critical",
                    description=f"Anomalous RWX memory region in {region.process_name} (PID {region.pid} at {region.path}. )",
                    matched_payload=f"0x{region.start_addr:x}-0x{region.end_addr:x} {region.permission} {region.path}",
                    mitre_id="T1055",
                    mitre_technique="Process Injection",
                    mitre_tactic="Defense Evasion"
                )
            )
    return matches

### detecting pointer corruption
def detect_pointer_corruption(snapshot: MemorySnapshot) -> list[ThreatMatch]:
    matches: list[ThreatMatch] = []
    for fp in snapshot.function_pointers:
        if not (fp.valid_min_addr <= fp.target_addr <= fp.valid_max_addr):
            matches.append(
                ThreatMatch(
                    category="Function Pointer Hook / Corruption",
                    severity="Critical",
                    description=f"Core function pointer '{fp.symbol_name}' (PID {fp.pid}) points outside valid module bounds.",
                    matched_payload=f"{fp.symbol_name}->0x{fp.target_addr:x} (valid: 0x{fp.valid_min_addr:x}-0x{fp.valid_max_addr:x})",
                    mitre_id="T1574",
                    mitre_technique="Hijack Execution Flow",
                    mitre_tactic="Persistence"
                )
            )
    return matches

### detecting fileless webshells
def detect_fileless_webshells(snapshot: MemorySnapshot) -> list[ThreatMatch]:
    matches: list[ThreatMatch] = []
    for script in snapshot.opcache_scripts:
        if not script.exists_on_disk or "eval()" in script.script_path:
            matches.append(
                ThreatMatch(
                    category="Fileless Web Shell",
                    severity="Critical",
                    description=f"Memory-resident PHP execution stream '{script.script_path}' at 0x{script.memory_addr:x} has no backing file on disk.",
                    matched_payload=f"path={script.script_path} addr=0x{script.memory_addr:x} preview={script.payload_preview[:60]}",
                    mitre_id="T1505.003",
                    mitre_technique="Server Software Component: Web Shell",
                    mitre_tactic="Persistence"
                )
            )
    return matches

### detecting suspicious process
WEB_WORKER_NAMES = {"php-fpm", "httpd", "nginx", "apache2", "w3wp.exe", "php-cgi"}
SHELL_NAMES = {"sh", "bash", "dash", "zsh", "ksh", "cmd.exe", "powershell.exe", "pwsh"}

def detect_suspicious_processes(snapshot: MemorySnapshot) -> list[ThreatMatch]:
    matches: list[ThreatMatch] = []
    for proc in snapshot.processes:
        proc_base = proc.name.lower().rsplit("/", 1)[-1]
        parent_base = proc.parent_name.lower().rsplit("/", 1)[-1]
        if parent_base in WEB_WORKER_NAMES and proc_base in SHELL_NAMES:
            matches.append(
                ThreatMatch(
                    category="Suspicious Worker Child Process",
                    severity="Critical",
                    description=f"Web worker '{proc.parent_name}' (PPID {proc.ppid}) spawned shell interpreter '{proc.name}' (PID {proc.pid}).",
                    matched_payload=f"{proc.parent_name}({proc.ppid}) -> {proc.name}({proc.pid}): {proc.cmdline}",
                    mitre_id="T1059",
                    mitre_technique="Command and Scripting Interpreter",
                    mitre_tactic="Execution"
                )
            )
    return matches

### unified function to detect threats in log entries
class ThreatDetector:
    def __init__(self, rules: Optional[list[SignatureRule]] = None, brute_force_threshold: int = 3):
        self.rules = rules or RULES
        self.brute_force_threshold = brute_force_threshold

    def analyze(self, entries: Iterable[LogEntry]) -> list[ThreatMatch]:
        # Runs both signature-based and brute-force detection on the provided log entries
        entry_list = list(entries) # pass multiple checks with generator
        all_matches: list[ThreatMatch] = []

        # per-entry signature detection
        for entry in entry_list:
            all_matches.extend(check_signatures(entry, self.rules))

        # multi-entry behavioral detection
        brute_force_matches = detect_brute_force(entry_list, threshold=self.brute_force_threshold, status_codes=(401, 403, 404))
        all_matches.extend(brute_force_matches)

        # PHP2Shell multi-entry stale worker detection
        all_matches.extend(detect_php2shell_stale_worker(entry_list))

        # WordPress upgrade race detection
        all_matches.extend(detect_wp_upgrade_race(entry_list, threshold=self.brute_force_threshold))  # Assuming snapshot has entries for log-like analysis

        return all_matches

    def analyze_memory(self, snapshot: MemorySnapshot) -> list[ThreatMatch]:
        all_matches: list[ThreatMatch] = []
        all_matches.extend(detect_heap_anomalies(snapshot))
        all_matches.extend(detect_rwx_regions(snapshot))
        all_matches.extend(detect_pointer_corruption(snapshot))
        all_matches.extend(detect_fileless_webshells(snapshot))
        all_matches.extend(detect_suspicious_processes(snapshot))
        return all_matches