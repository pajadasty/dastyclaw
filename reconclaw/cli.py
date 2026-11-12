from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from reconclaw import __version__
from reconclaw.domain_recon import DomainRecon
from reconclaw.headers_audit import SecurityHeadersAuditor
from reconclaw.reporter import ReconReporter
from reconclaw.user_hunter import HunterResult, UserHunter

# ANSI Terminal Colors
BOLD = "\033[1m"
RESET = "\033[0m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"
GRAY = "\033[90m"
MAGENTA = "\033[35m"


def print_banner() -> None:
    banner = f"""{BOLD}{CYAN}
  ____                      ____ _                 
 |  _ \\ ___  ___ ___  _ __ / ___| | __ ___      __ 
 | |_) / _ \\/ __/ _ \\| '_ \\ |   | |/ _` \\ \\ /\\ / / 
 |  _ <  __/ (_| (_) | | | | |___| | (_| |\\ V  V /  
 |_| \\_\\___|\\___\\___/|_| |_|\\____|_|\\__,_| \\_/\\_/   {RESET}{GRAY}v{__version__}{RESET}
 {GRAY}Tactical OSINT Reconnaissance & Footprinting Toolkit{RESET}
"""
    print(banner)


async def cmd_user(username: str, concurrency: int, timeout: float, output_dir: Path | None) -> None:
    print(f"{BOLD}[*] Initiating Username Hunter for target:{RESET} {CYAN}@{username}{RESET}")
    hunter = UserHunter(concurrency=concurrency, timeout_sec=timeout)

    found_count = 0

    def on_result(r: HunterResult) -> None:
        nonlocal found_count
        if r.found:
            found_count += 1
            print(f"  {GREEN}[+] FOUND{RESET}  {BOLD}{r.platform:<14}{RESET} {r.url} {GRAY}({r.elapsed_ms}ms){RESET}")

    results = await hunter.hunt(username, on_result=on_result)
    print(f"\n{BOLD}[*] Hunter complete:{RESET} {GREEN}{found_count}{RESET} active profiles found across {len(results)} platforms.\n")

    if output_dir:
        reporter = ReconReporter(f"user_{username}")
        md_file = output_dir / f"{username}_user_dossier.md"
        json_file = output_dir / f"{username}_user_dossier.json"
        reporter.export_markdown(md_file, hunter_results=results)
        reporter.export_json(json_file, hunter_results=results)
        print(f"  {GRAY}Report saved -> {md_file}{RESET}")
        print(f"  {GRAY}JSON data saved -> {json_file}{RESET}\n")


async def cmd_domain(domain: str, timeout: float, output_dir: Path | None) -> None:
    print(f"{BOLD}[*] Initiating Domain Reconnaissance for:{RESET} {CYAN}{domain}{RESET}")
    recon = DomainRecon(timeout_sec=timeout)
    auditor = SecurityHeadersAuditor(timeout_sec=timeout)

    report, headers_report = await asyncio.gather(
        recon.scan_domain(domain),
        auditor.audit(domain),
    )

    # 1. Subdomains
    print(f"\n{BOLD}[+] Certificate Transparency (crt.sh):{RESET} Discovered {GREEN}{len(report.subdomains)}{RESET} subdomains")
    for sub in report.subdomains[:12]:
        print(f"    {GRAY}•{RESET} {sub}")
    if len(report.subdomains) > 12:
        print(f"    {GRAY}... and {len(report.subdomains) - 12} more.{RESET}")

    # 2. DNS
    print(f"\n{BOLD}[+] DNS Resolution:{RESET}")
    for k, v in report.dns_records.items():
        if v:
            print(f"    {BOLD}{k:<6}{RESET} {', '.join(v)}")

    # 3. Mail Security
    if report.mail_security:
        ms = report.mail_security
        color = RED if ms.spoofable else GREEN
        status_text = "VULNERABLE TO SPOOFING" if ms.spoofable else "PROTECTED AGAINST SPOOFING"
        print(f"\n{BOLD}[+] Email Anti-Spoofing Audit:{RESET}")
        print(f"    Status: {color}{status_text}{RESET}")
        print(f"    SPF:    {ms.spf_strictness}")
        print(f"    DMARC:  {ms.dmarc_policy}")
        print(f"    Note:   {GRAY}{ms.summary}{RESET}")

    # 4. Security Headers
    print(f"\n{BOLD}[+] Security Headers Audit:{RESET} Grade: {BOLD}{CYAN}{headers_report.grade}{RESET} ({headers_report.score}/100)")
    for c in headers_report.checks:
        icon = f"{GREEN}PASS{RESET}" if c.present else f"{RED}MISSING{RESET}"
        print(f"    [{icon}] {c.header_name:<28} {GRAY}{c.description[:60]}{RESET}")

    print()

    if output_dir:
        reporter = ReconReporter(f"domain_{report.domain}")
        md_file = output_dir / f"{report.domain}_domain_dossier.md"
        json_file = output_dir / f"{report.domain}_domain_dossier.json"
        reporter.export_markdown(md_file, domain_report=report, headers_report=headers_report)
        reporter.export_json(json_file, domain_report=report, headers_report=headers_report)
        print(f"  {GRAY}Report saved -> {md_file}{RESET}")
        print(f"  {GRAY}JSON data saved -> {json_file}{RESET}\n")


async def async_main() -> None:
    parser = argparse.ArgumentParser(
        prog="reconclaw",
        description="Tactical OSINT Reconnaissance & Digital Footprinting Toolkit.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="subcommand", help="Module to execute")

    # Command: user
    user_p = subparsers.add_parser("user", help="Hunt username across 35+ online platforms")
    user_p.add_argument("username", help="Target username or handle to investigate")

    # Command: domain
    domain_p = subparsers.add_parser("domain", help="Enumerate subdomains, DNS, SPF/DMARC & security headers")
    domain_p.add_argument("domain", help="Target domain (e.g. example.com)")

    # Global options
    for p in (user_p, domain_p):
        p.add_argument("-o", "--output-dir", default="./reports", help="Directory to save reports (default: ./reports)")
        p.add_argument("-c", "--concurrency", type=int, default=25, help="Concurrent workers (default: 25)")
        p.add_argument("-t", "--timeout", type=float, default=6.0, help="Request timeout in seconds (default: 6.0)")
        p.add_argument("--no-export", action="store_true", help="Do not write report files to disk")

    args = parser.parse_args()

    print_banner()

    if not args.subcommand:
        parser.print_help()
        sys.exit(1)

    out_dir = None if args.no_export else Path(args.output_dir)

    if args.subcommand == "user":
        await cmd_user(args.username, args.concurrency, args.timeout, out_dir)
    elif args.subcommand == "domain":
        await cmd_domain(args.domain, args.timeout, out_dir)


def main() -> None:
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Interrupted by user.{RESET}")


if __name__ == "__main__":
    main()
