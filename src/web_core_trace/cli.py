import argparse
import sys
from pathlib import Path
from typing import Optional
from web_core_trace.parser import parse_file
from web_core_trace.detector import ThreatDetector
from web_core_trace.enricher import IPEnricher, enrich_ips
from web_core_trace.memory_parser import (
    acquire_and_scan,
    inspect_live_host,
    parse_memory_dump
)
from web_core_trace.reporter import (
    build_forensic_report,
    generate_json_report,
    generate_html_report,
    ForensicReport
)

### args
def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="Web Core Trace",
        description="WebCoreTrace: Dual-Mode Web Access Log & Host Memory Forensic Triage Tool"
    )
    parser.add_argument(
        "--mode",
        choices=["web-log-triage", "core"],
        default="web-log-triage",
        help="Execution mode: 'web-log-triage' (access logs) or 'core' (RAM/process memory)" 
    )
    parser.add_argument("-f", "--format", choices=["console", "html", "json"], default="console", help="Report format: console, html, or json (default: console)")
    parser.add_argument("-o", "--output", type=str, help="Output file path for html/json")
    parser.add_argument("log_file", nargs="?", default=None, help="Path to the access log file (for web-log-triage mode; Combined/Common format)")
    parser.add_argument("--threshold", type=int, default=3, help="Brute-force 404/403 threshold (default: 3)")
    parser.add_argument("--no-geoip", action="store_true", help="Disable online GeoIP lookups (offline mode)")

    # Core / Memory Options
    parser.add_argument("--memory-dump", type=str, help="Path to static RAM/core dump or Volatiility 3 JSON snapshot")
    parser.add_argument("--live-host", action="store_true", help="Inspect live host processes via /proc")
    parser.add_argument("--acquire-and-scan", choices=["avml", "gcore"], help="Acquire memory with avml/gcore and scan immediately")
    parser.add_argument("--pid", type=int, help="Target process ID for --live-host or --acquire-and-scan")
    parser.add_argument("--wp-root", type=str, help="Path to WordPress root directory to inspect filesystem artifacts")
    
    return parser.parse_args(args)

### prints clean ASCII SOC triage summary
def _print_console_summary(report: ForensicReport) -> None:
    print("\n" + "=" * 65)
    print(" WEB CORE TRACE - FORENSIC SUMMARY")
    print("=" * 65)
    print(f" Total Requests Analyzed : {report.total_requests}")
    print(f" Unique IP Addresses     : {report.unique_ips}")
    print(f" Total Threats Detected  : {report.total_threats}")
    print("=" * 65)

    print("\n[+] Top Offending IPs & Network Geolocation:")
    if report.top_attacking_ips:
        for ip, count in report.top_attacking_ips:
            enrichment = report.ip_enrichments.get(ip)
            geo = f"{enrichment.country} ({enrichment.city})" if enrichment else "Unknown"
            print(f"  {ip:<16} : {count:>2} alerts | Location: {geo}")
    else:
        print("  None detected (Clean traffic)")

    print("\n[+] Threat Categories Breakdown:")
    for cat, count in report.category_distribution.items():
        print(f" {cat:<22} : {count}")

    print("\n[+] Detailed Threat Findings:")
    if report.threats:
        for i, t in enumerate(report.threats, 1):
            if t.entry is not None:
                ts = t.entry.timestamp.strftime("%Y-%m-%d %H:%M:%S") if t.entry.timestamp else "-"
                source_ip = t.entry.ip
                target_context = t.entry.decoded_uri[:65]
            else:
                ts = "-"
                source_ip = "host-memory"
                target_context = t.description[:65]

            print(f"  [{i:>2}] [{t.severity:<8}] {t.category:<12} (MITRE {t.mitre_id or '-'}) from {source_ip}")
            print(f"     Payload : {t.matched_payload[:55]}")
            print(f"     Context : {target_context}")
    else:
        print("  Clean traffic. No security alerts identified.")
    print("=" * 65 + "\n")

### main pipline
# verify if logs exists
def main_pipeline(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    detector = ThreatDetector(brute_force_threshold=args.threshold)

    is_core_mode = (
        args.mode == "core"
        or args.memory_dump is not None
        or args.live_host
        or args.acquire_and_scan is not None
    )

    if is_core_mode:
        try:
            if args.memory_dump:
                snapshot = parse_memory_dump(args.memory_dump)
            elif args.live_host:
                pids = [args.pid] if args.pid is not None else None
                snapshot = inspect_live_host(pids=pids)
            elif args.acquire_and_scan:
                snapshot = acquire_and_scan(tool=args.acquire_and_scan, target_pid=args.pid)
            else:
                print("[-] Error: Core Mode requires --memory-dump, --live-host, or --acquire-and-scan.", file=sys.stderr)
                return 1
        except Exception as exec:
            print(f"[-] Error during memory ingestion: {exec}", file=sys.stderr)
            return 1

        threats = detector.analyze_memory(snapshot)
        if args.wp_root:
            threats.extend(detector.analyze_wp_filesystem(args.wp_root))
        report = build_forensic_report(entries=[], threats=threats, ip_enrichments={})
    else:
        if not args.log_file and not args.wp_root:
            print("[-] Error: log_file (or --wp-root) is required in web-log-triage mode.", file=sys.stderr)
            return 1

        entries = []
        if args.log_file:
            log_path = Path(args.log_file)
            if not log_path.is_file():
                print(f"[-] Error File not found: {args.log_file}", file=sys.stderr)
                return 1

            # run pipeline
            entries = list(parse_file(log_path))
            if not entries and not args.wp_root:
                print("[-] Warning: No valid log entries found to parse.", file=sys.stderr)
                return 0

        # threat detection
        threats = detector.analyze(entries) if entries else []
        if args.wp_root:
            threats.extend(detector.analyze_wp_filesystem(args.wp_root))

        # IP Enrichment
        enricher = IPEnricher(enable_geoip=not args.no_geoip)
        enrichments = enrich_ips(entries, enricher) if entries else {}

        # Metrics & Reporting
        report = build_forensic_report(entries, threats, enrichments)

    ### output handling
    if args.format == "json":
        json_output = generate_json_report(report, args.output)
        if args.output:
            print(f"[+] Forensic JSON report saved to: {args.output}")
        else:
            print(json_output)

    elif args.format == "html":
        out_file = args.output or "forensic_report.html"
        generate_html_report(report, out_file)
        print(f"[+] Forensic HTML dashboard generated: {out_file}")

    else: # default to console
        _print_console_summary(report)

    return 0

if __name__ == "__main__":
    sys.exit(main_pipeline())