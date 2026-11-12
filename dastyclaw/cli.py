from __future__ import annotations

import argparse
import asyncio
import sys
import webbrowser
from pathlib import Path
from typing import Dict, List, Optional

from dastyclaw import __version__
from dastyclaw.domain_recon import DomainRecon
from dastyclaw.dork_generator import DorkGenerator
from dastyclaw.email_hunter import EmailFootprintResult, EmailHunter
from dastyclaw.headers_audit import SecurityHeadersAuditor
from dastyclaw.phone_hunter import PhoneHunter, PhoneIntelResult
from dastyclaw.reporter import ReconReporter
from dastyclaw.user_hunter import HunterResult, UserHunter

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
  ____            _        ____ _                 
 |  _ \\  __ _ ___| |_ _   / ___| | __ ___      __ 
 | | | |/ _` / __| __| | | |   | |/ _` \\ \\ /\\ / / 
 | |_| | (_| \\__ \\ |_| |_| |___| | (_| |\\ V  V /  
 |____/ \\__,_|___/\\__|\\__, |\\____|_|\\__,_| \\_/\\_/   {RESET}{GRAY}v{__version__}{RESET}
                      {CYAN}|___/{RESET}
 {GRAY}Tactical OSINT Reconnaissance & Footprinting Toolkit by pajadasty{RESET}
"""
    print(banner)


def prompt_str(label: str, default: str = "") -> str:
    prompt_text = f"{BOLD}{CYAN}[?]{RESET} {label}"
    if default:
        prompt_text += f" {GRAY}[{default}]{RESET}"
    prompt_text += ": "
    try:
        val = input(prompt_text).strip()
        return val if val else default
    except (EOFError, KeyboardInterrupt):
        return default


async def cmd_user(username: str, concurrency: int, timeout: float, output_dir: Path | None, open_browser: bool = False) -> None:
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
        html_file = output_dir / f"{username}_user_dossier.html"

        reporter.export_markdown(md_file, hunter_results=results)
        reporter.export_json(json_file, hunter_results=results)
        reporter.export_html(html_file, hunter_results=results)

        print(f"  {GRAY}Markdown Report -> {md_file}{RESET}")
        print(f"  {GRAY}JSON Data       -> {json_file}{RESET}")
        print(f"  {GREEN}HTML Dossier    -> {html_file}{RESET}\n")

        if open_browser:
            webbrowser.open(html_file.resolve().as_uri())


async def cmd_domain(domain: str, timeout: float, output_dir: Path | None, open_browser: bool = False) -> None:
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
        print(f"  {GRAY}Markdown Report -> {md_file}{RESET}")
        print(f"  {GRAY}JSON Data       -> {json_file}{RESET}\n")


async def cmd_hunt(
    username: Optional[str],
    real_name: Optional[str],
    email: Optional[str],
    location: Optional[str],
    phone: Optional[str],
    concurrency: int,
    timeout: float,
    output_dir: Path | None,
    interactive: bool = False,
    open_browser: bool = False,
) -> None:
    # Interactive wizard if requested or all empty
    if interactive or (not username and not real_name and not email and not phone):
        print(f"{BOLD}[*] Tactical Target Profiler (Interactive OSINT Wizard){RESET}")
        print(f"{GRAY}Enter known intelligence attributes (press Enter to skip):{RESET}\n")

        username = prompt_str("Target handle / username (e.g. pajadasty)", username or "")
        real_name = prompt_str("Full Name (e.g. 'Pavel Novak')", real_name or "")
        email = prompt_str("Email address (e.g. target@example.com)", email or "")
        location = prompt_str("Location / City (e.g. 'Prague, Czechia')", location or "")
        phone = prompt_str("Phone number (e.g. '+420123456789')", phone or "")
        print()

    if not username and not real_name and not email and not phone:
        print(f"{RED}[!] No target intelligence attributes provided.{RESET}")
        return

    primary_target = username or real_name or email or phone or "target"
    safe_target_name = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in primary_target)

    person_profile: Dict[str, str] = {}
    if username:
        person_profile["username"] = username
    if real_name:
        person_profile["full_name"] = real_name
    if email:
        person_profile["email"] = email
    if location:
        person_profile["location"] = location
    if phone:
        person_profile["phone"] = phone

    hunter_results: Optional[List[HunterResult]] = None
    email_result: Optional[EmailFootprintResult] = None
    phone_result: Optional[PhoneIntelResult] = None

    # 1. Username Hunter
    if username:
        print(f"{BOLD}[1/4] Hunting digital footprint for alias:{RESET} {CYAN}@{username}{RESET}")
        hunter = UserHunter(concurrency=concurrency, timeout_sec=timeout)

        found_count = 0

        def on_result(r: HunterResult) -> None:
            nonlocal found_count
            if r.found:
                found_count += 1
                print(f"  {GREEN}[+] FOUND{RESET} {BOLD}{r.platform:<14}{RESET} {r.url} {GRAY}({r.elapsed_ms}ms){RESET}")

        hunter_results = await hunter.hunt(username, on_result=on_result)
        print(f"  {BOLD}Discovery complete:{RESET} {GREEN}{found_count}{RESET} active profiles found.\n")

    # 2. Email Intelligence
    if email:
        print(f"{BOLD}[2/4] Auditing email footprint:{RESET} {CYAN}{email}{RESET}")
        email_hunter = EmailHunter(timeout_sec=timeout)
        email_result = await email_hunter.hunt(email)

        if email_result.is_valid_format:
            mx_icon = f"{GREEN}VALID (ACCEPTS MAIL){RESET}" if email_result.mx_valid else f"{YELLOW}NO MX DETECTED{RESET}"
            print(f"  [+] Domain: {email_result.domain} (MX: {mx_icon})")
            if email_result.gravatar_found:
                print(f"  {GREEN}[+] Gravatar Profile Detected:{RESET} {email_result.gravatar_profile_url}")
                if email_result.gravatar_display_name:
                    print(f"      Display Name: {BOLD}{email_result.gravatar_display_name}{RESET}")
            if email_result.github_user:
                print(f"  {GREEN}[+] Matching GitHub Account:{RESET} https://github.com/{email_result.github_user}")
        else:
            print(f"  {RED}[!] Invalid email syntax.{RESET}")
        print()

    # 3. Telephony Intelligence
    if phone:
        print(f"{BOLD}[3/4] Profiling phone number:{RESET} {CYAN}{phone}{RESET}")
        phone_result = PhoneHunter.analyze(phone)
        if phone_result.is_valid_format:
            print(f"  [+] Region: {GREEN}{phone_result.country_hint}{RESET} ({phone_result.cleaned_number})")
            print(f"  [+] WhatsApp Link: {phone_result.whatsapp_link}")
            print(f"  [+] Telegram Link: {phone_result.telegram_link}")
        else:
            print(f"  {RED}[!] Invalid telephone structure.{RESET}")
        print()

    # 4. Tactical OSINT Dorks
    step_label = "[4/4]" if (phone and email and username) else "[*]"
    print(f"{BOLD}{step_label} Generating tactical search dorks...{RESET}")
    dorks = DorkGenerator.generate(
        username=username,
        real_name=real_name,
        email=email,
        location=location,
        phone=phone,
    )
    for d in dorks:
        print(f"  {MAGENTA}• {d.category}:{RESET} {d.description}")
        print(f"    {GRAY}Google:{RESET} {d.google_url}")
    print()

    # Export Dossier
    if output_dir:
        reporter = ReconReporter(f"investigation_{safe_target_name}")
        md_file = output_dir / f"{safe_target_name}_investigation_dossier.md"
        json_file = output_dir / f"{safe_target_name}_investigation_dossier.json"
        html_file = output_dir / f"{safe_target_name}_investigation_dossier.html"

        reporter.export_markdown(
            md_file,
            hunter_results=hunter_results,
            email_report=email_result,
            phone_report=phone_result,
            dorks=dorks,
            person_profile=person_profile,
        )
        reporter.export_json(
            json_file,
            hunter_results=hunter_results,
            email_report=email_result,
            phone_report=phone_result,
            dorks=dorks,
            person_profile=person_profile,
        )
        reporter.export_html(
            html_file,
            hunter_results=hunter_results,
            email_report=email_result,
            phone_report=phone_result,
            dorks=dorks,
            person_profile=person_profile,
        )

        print(f"{BOLD}[*] Intelligence Dossier Generated:{RESET}")
        print(f"  {GRAY}Markdown Report -> {md_file}{RESET}")
        print(f"  {GRAY}JSON Data       -> {json_file}{RESET}")
        print(f"  {GREEN}Interactive HTML -> {html_file}{RESET}\n")

        if open_browser:
            webbrowser.open(html_file.resolve().as_uri())


async def async_main() -> None:
    parser = argparse.ArgumentParser(
        prog="dastyclaw",
        description="Tactical OSINT Reconnaissance & Digital Footprinting Toolkit by pajadasty.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="subcommand", help="Module to execute")

    # Command: hunt (Smart Multi-Vector Person Profiler)
    hunt_p = subparsers.add_parser("hunt", help="Smart multi-vector OSINT investigation (Username, Name, Email, Phone, Location)")
    hunt_p.add_argument("-u", "--username", help="Target username or handle (e.g. pajadasty)")
    hunt_p.add_argument("-n", "--name", help="Target full name (e.g. 'Pavel Novak')")
    hunt_p.add_argument("-e", "--email", help="Target email address")
    hunt_p.add_argument("-p", "--phone", help="Target telephone number (e.g. +420...)")
    hunt_p.add_argument("-l", "--location", help="Target city or location")
    hunt_p.add_argument("-i", "--interactive", action="store_true", help="Launch interactive step-by-step wizard")
    hunt_p.add_argument("-b", "--open", action="store_true", help="Automatically open generated HTML dossier in default web browser")

    # Command: user
    user_p = subparsers.add_parser("user", help="Hunt username across 30+ online platforms")
    user_p.add_argument("username", nargs="?", default="", help="Target username or handle to investigate")
    user_p.add_argument("-b", "--open", action="store_true", help="Automatically open generated HTML dossier in default web browser")

    # Command: domain
    domain_p = subparsers.add_parser("domain", help="Enumerate subdomains, DNS, SPF/DMARC & security headers")
    domain_p.add_argument("domain", help="Target domain (e.g. example.com)")

    # Global options
    for p in (hunt_p, user_p, domain_p):
        p.add_argument("-o", "--output-dir", default="./reports", help="Directory to save reports (default: ./reports)")
        p.add_argument("-c", "--concurrency", type=int, default=25, help="Concurrent workers (default: 25)")
        p.add_argument("-t", "--timeout", type=float, default=6.0, help="Request timeout in seconds (default: 6.0)")
        p.add_argument("--no-export", action="store_true", help="Do not write report files to disk")

    args = parser.parse_args()

    print_banner()

    if not args.subcommand:
        # Default to interactive hunt wizard if called with no arguments
        out_dir = Path("./reports")
        await cmd_hunt(None, None, None, None, None, 25, 6.0, out_dir, interactive=True)
        return

    out_dir = None if args.no_export else Path(args.output_dir)

    if args.subcommand == "hunt":
        await cmd_hunt(
            username=args.username,
            real_name=args.name,
            email=args.email,
            location=args.location,
            phone=args.phone,
            concurrency=args.concurrency,
            timeout=args.timeout,
            output_dir=out_dir,
            interactive=args.interactive,
            open_browser=args.open,
        )
    elif args.subcommand == "user":
        if not args.username:
            username = prompt_str("Enter handle / username to investigate")
            if not username:
                print(f"{RED}[!] No username provided.{RESET}")
                return
        else:
            username = args.username
        await cmd_user(username, args.concurrency, args.timeout, out_dir, open_browser=args.open)
    elif args.subcommand == "domain":
        await cmd_domain(args.domain, args.timeout, out_dir)


def main() -> None:
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Interrupted by user.{RESET}")


if __name__ == "__main__":
    main()
