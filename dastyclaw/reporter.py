from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from dastyclaw.domain_recon import DomainReconReport
from dastyclaw.headers_audit import SecurityHeadersReport
from dastyclaw.user_hunter import HunterResult
from dastyclaw.email_hunter import EmailFootprintResult
from dastyclaw.dork_generator import OsintDork


class ReconReporter:
    def __init__(self, target_name: str):
        self.target_name = target_name
        self.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def export_json(
        self,
        filepath: str | Path,
        hunter_results: Optional[List[HunterResult]] = None,
        domain_report: Optional[DomainReconReport] = None,
        headers_report: Optional[SecurityHeadersReport] = None,
        email_report: Optional[EmailFootprintResult] = None,
        dorks: Optional[List[OsintDork]] = None,
        person_profile: Optional[Dict[str, str]] = None,
    ) -> Path:
        out_path = Path(filepath)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        data: Dict[str, Any] = {
            "target": self.target_name,
            "generated_at": self.timestamp,
        }

        if person_profile:
            data["person_profile"] = person_profile

        if hunter_results is not None:
            data["username_intel"] = {
                "total_checked": len(hunter_results),
                "total_found": len([r for r in hunter_results if r.found]),
                "accounts": [
                    {
                        "platform": r.platform,
                        "url": r.url,
                        "category": r.category,
                        "status_code": r.status_code,
                        "latency_ms": r.elapsed_ms,
                    }
                    for r in hunter_results if r.found
                ],
            }

        if email_report is not None:
            data["email_intel"] = {
                "email": email_report.email,
                "is_valid_format": email_report.is_valid_format,
                "domain": email_report.domain,
                "mx_valid": email_report.mx_valid,
                "gravatar_found": email_report.gravatar_found,
                "gravatar_profile_url": email_report.gravatar_profile_url,
                "gravatar_display_name": email_report.gravatar_display_name,
                "gravatar_avatar_url": email_report.gravatar_avatar_url,
                "github_user": email_report.github_user,
                "github_profile_url": email_report.github_profile_url,
                "notes": email_report.notes,
            }

        if dorks:
            data["osint_dorks"] = [
                {
                    "category": d.category,
                    "description": d.description,
                    "query": d.query,
                    "google_url": d.google_url,
                    "duckduckgo_url": d.duckduckgo_url,
                }
                for d in dorks
            ]

        if domain_report is not None:
            data["domain_intel"] = {
                "domain": domain_report.domain,
                "subdomains_count": len(domain_report.subdomains),
                "subdomains": domain_report.subdomains,
                "dns_records": domain_report.dns_records,
                "mail_security": {
                    "has_spf": domain_report.mail_security.has_spf if domain_report.mail_security else False,
                    "spf_strictness": domain_report.mail_security.spf_strictness if domain_report.mail_security else "Missing",
                    "spf_record": domain_report.mail_security.spf_record if domain_report.mail_security else None,
                    "has_dmarc": domain_report.mail_security.has_dmarc if domain_report.mail_security else False,
                    "dmarc_policy": domain_report.mail_security.dmarc_policy if domain_report.mail_security else "Missing",
                    "dmarc_record": domain_report.mail_security.dmarc_record if domain_report.mail_security else None,
                    "spoofable": domain_report.mail_security.spoofable if domain_report.mail_security else True,
                    "summary": domain_report.mail_security.summary if domain_report.mail_security else "",
                } if domain_report.mail_security else None,
            }

        if headers_report is not None:
            data["security_headers"] = {
                "url": headers_report.url,
                "score": headers_report.score,
                "grade": headers_report.grade,
                "server_tokens": headers_report.server_tokens,
                "powered_by": headers_report.powered_by,
                "checks": [
                    {
                        "header": c.header_name,
                        "present": c.present,
                        "severity": c.severity,
                        "description": c.description,
                        "recommendation": c.recommendation,
                    }
                    for c in headers_report.checks
                ],
            }

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        return out_path

    def export_markdown(
        self,
        filepath: str | Path,
        hunter_results: Optional[List[HunterResult]] = None,
        domain_report: Optional[DomainReconReport] = None,
        headers_report: Optional[SecurityHeadersReport] = None,
        email_report: Optional[EmailFootprintResult] = None,
        dorks: Optional[List[OsintDork]] = None,
        person_profile: Optional[Dict[str, str]] = None,
    ) -> Path:
        out_path = Path(filepath)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        lines: List[str] = [
            f"# OSINT Reconnaissance Dossier: {self.target_name}",
            f"> Generated by DastyClaw on {self.timestamp}",
            "",
            "---",
            "",
        ]

        # 0. Target Profile
        if person_profile:
            lines.extend([
                "## 👤 Target Profile Information",
                "",
            ])
            for k, v in person_profile.items():
                if v:
                    lines.append(f"- **{k.replace('_', ' ').title()}**: `{v}`")
            lines.extend(["", "---", ""])

        # 1. Username Intelligence
        if hunter_results is not None:
            found_accounts = [r for r in hunter_results if r.found]
            lines.extend([
                "## 1. Digital Identity & Profile Footprint",
                f"- **Platforms Checked**: {len(hunter_results)}",
                f"- **Active Profiles Discovered**: {len(found_accounts)}",
                "",
                "| Platform | Category | URL | Response |",
                "|---|---|---|---|",
            ])
            for r in found_accounts:
                lines.append(f"| **{r.platform}** | {r.category} | [{r.url}]({r.url}) | {r.elapsed_ms}ms |")
            lines.extend(["", "---", ""])

        # 2. Email Intelligence
        if email_report is not None:
            lines.extend([
                "## 2. Email Intelligence & Linked Identity",
                f"- **Email**: `{email_report.email}`",
                f"- **Domain MX Status**: {'Active (Valid MX)' if email_report.mx_valid else 'No MX records'}",
                f"- **Gravatar Linked Profile**: {'Yes' if email_report.gravatar_found else 'None'}",
            ])
            if email_report.gravatar_profile_url:
                lines.append(f"  - Profile URL: [{email_report.gravatar_profile_url}]({email_report.gravatar_profile_url})")
            if email_report.gravatar_display_name:
                lines.append(f"  - Display Name: `{email_report.gravatar_display_name}`")
            if email_report.github_user:
                lines.append(f"- **GitHub User Matching Email**: [{email_report.github_user}]({email_report.github_profile_url})")
            lines.extend(["", "---", ""])

        # 3. Tactical OSINT Dorks
        if dorks:
            lines.extend([
                "## 3. Tactical OSINT Search Dorks",
                "Direct links for deep investigations across search engines:",
                "",
            ])
            for d in dorks:
                lines.extend([
                    f"### 🔎 {d.category}",
                    f"*{d.description}*",
                    "",
                    f"```text\n{d.query}\n```",
                    f"- [Search on Google]({d.google_url}) | [Search on DuckDuckGo]({d.duckduckgo_url})",
                    "",
                ])
            lines.extend(["---", ""])

        # 4. Domain & Subdomains
        if domain_report is not None:
            lines.extend([
                f"## 4. Domain Intelligence: `{domain_report.domain}`",
                f"- **Total Subdomains Discovered**: {len(domain_report.subdomains)}",
                "",
                "### DNS Configuration",
            ])
            for k, records in domain_report.dns_records.items():
                if records:
                    lines.append(f"- **{k}**: {', '.join(records)}")

            if domain_report.mail_security:
                ms = domain_report.mail_security
                lines.extend([
                    "",
                    "### Email Anti-Spoofing Security",
                    f"- **Spoofable**: {'⚠️ YES (Vulnerable)' if ms.spoofable else '✅ NO (Protected)'}",
                    f"- **SPF Policy**: `{ms.spf_strictness}`",
                    f"- **DMARC Policy**: `{ms.dmarc_policy}`",
                    f"- **Assessment**: {ms.summary}",
                ])

            if domain_report.subdomains:
                lines.extend([
                    "",
                    f"### Discovered Subdomains ({len(domain_report.subdomains)})",
                    "<details><summary>Click to view full list</summary>\n",
                ])
                for sub in domain_report.subdomains:
                    lines.append(f"- `{sub}`")
                lines.append("\n</details>")

            lines.extend(["", "---", ""])

        # 5. Security Headers
        if headers_report is not None:
            lines.extend([
                "## 5. Security Headers Audit",
                f"- **Grade**: **{headers_report.grade}** ({headers_report.score}/100)",
                "",
                "| Header | Status | Severity | Description |",
                "|---|---|---|---|",
            ])
            for c in headers_report.checks:
                status = "✅ PASS" if c.present else "❌ MISSING"
                lines.append(f"| `{c.header_name}` | {status} | {c.severity} | {c.description} |")
            lines.append("")

        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        return out_path
