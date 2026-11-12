from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from dastyclaw.domain_recon import DomainReconReport
from dastyclaw.dork_generator import OsintDork
from dastyclaw.email_hunter import EmailFootprintResult
from dastyclaw.headers_audit import SecurityHeadersReport
from dastyclaw.phone_hunter import PhoneIntelResult
from dastyclaw.user_hunter import HunterResult


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
        phone_report: Optional[PhoneIntelResult] = None,
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
            data["target_profile"] = person_profile

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

        if phone_report is not None:
            data["phone_intel"] = {
                "raw_number": phone_report.raw_number,
                "cleaned_number": phone_report.cleaned_number,
                "is_valid": phone_report.is_valid_format,
                "country": phone_report.country_hint,
                "whatsapp_link": phone_report.whatsapp_link,
                "telegram_link": phone_report.telegram_link,
                "notes": phone_report.notes,
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
        phone_report: Optional[PhoneIntelResult] = None,
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

        if person_profile:
            lines.extend([
                "## 👤 Target Profile Information",
                "",
            ])
            for k, v in person_profile.items():
                if v:
                    lines.append(f"- **{k.replace('_', ' ').title()}**: `{v}`")
            lines.extend(["", "---", ""])

        if hunter_results is not None:
            found_accounts = [r for r in hunter_results if r.found]
            lines.extend([
                "## 1. Digital Identity & Profile Footprint",
                f"- **Platforms Probed**: {len(hunter_results)}",
                f"- **Active Profiles Discovered**: {len(found_accounts)}",
                "",
                "| Platform | Category | URL | Response |",
                "|---|---|---|---|",
            ])
            for r in found_accounts:
                lines.append(f"| **{r.platform}** | {r.category} | [{r.url}]({r.url}) | {r.elapsed_ms}ms |")
            lines.extend(["", "---", ""])

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

        if phone_report is not None and phone_report.is_valid_format:
            lines.extend([
                "## 3. Telephony Intelligence",
                f"- **Number**: `{phone_report.cleaned_number}`",
                f"- **Country Hint**: {phone_report.country_hint}",
                f"- **WhatsApp Direct Link**: [{phone_report.whatsapp_link}]({phone_report.whatsapp_link})",
                f"- **Telegram Direct Link**: [{phone_report.telegram_link}]({phone_report.telegram_link})",
                "",
                "---",
                "",
            ])

        if dorks:
            lines.extend([
                "## 4. Tactical OSINT Search Dorks",
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

        if domain_report is not None:
            lines.extend([
                f"## 5. Domain Intelligence: `{domain_report.domain}`",
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

        if headers_report is not None:
            lines.extend([
                "## 6. Security Headers Audit",
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

    def export_html(
        self,
        filepath: str | Path,
        hunter_results: Optional[List[HunterResult]] = None,
        domain_report: Optional[DomainReconReport] = None,
        headers_report: Optional[SecurityHeadersReport] = None,
        email_report: Optional[EmailFootprintResult] = None,
        phone_report: Optional[PhoneIntelResult] = None,
        dorks: Optional[List[OsintDork]] = None,
        person_profile: Optional[Dict[str, str]] = None,
    ) -> Path:
        out_path = Path(filepath)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        found_accounts = [r for r in (hunter_results or []) if r.found]

        accounts_html = ""
        for r in found_accounts:
            accounts_html += f"""
            <div class="account-card">
                <div class="account-header">
                    <span class="platform-badge">{html.escape(r.category)}</span>
                    <span class="latency-badge">{r.elapsed_ms}ms</span>
                </div>
                <h3 class="account-name">{html.escape(r.platform)}</h3>
                <a class="account-link" href="{html.escape(r.url)}" target="_blank" rel="noopener noreferrer">
                    {html.escape(r.url)}
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg>
                </a>
            </div>
            """

        dorks_html = ""
        for d in (dorks or []):
            dorks_html += f"""
            <div class="dork-card">
                <div class="dork-title">
                    <span class="dork-category">{html.escape(d.category)}</span>
                    <span class="dork-desc">{html.escape(d.description)}</span>
                </div>
                <pre class="dork-query"><code>{html.escape(d.query)}</code></pre>
                <div class="dork-actions">
                    <a class="btn-dork google" href="{html.escape(d.google_url)}" target="_blank">Google Search</a>
                    <a class="btn-dork ddg" href="{html.escape(d.duckduckgo_url)}" target="_blank">DuckDuckGo</a>
                </div>
            </div>
            """

        profile_rows = ""
        if person_profile:
            for k, v in person_profile.items():
                if v:
                    profile_rows += f"""<div class="meta-item"><span class="meta-label">{html.escape(k.replace('_', ' ').title())}:</span> <span class="meta-val">{html.escape(v)}</span></div>"""

        email_html = ""
        if email_report:
            mx_badge = '<span class="badge pass">Active Mail Server (MX Valid)</span>' if email_report.mx_valid else '<span class="badge warn">No MX Records</span>'
            gravatar_info = ""
            if email_report.gravatar_found:
                avatar_img = f'<img src="{html.escape(email_report.gravatar_avatar_url)}" class="gravatar-img" alt="Avatar"/>' if email_report.gravatar_avatar_url else ''
                gravatar_info = f"""
                <div class="gravatar-box">
                    {avatar_img}
                    <div>
                        <strong>Gravatar Profile Found</strong>: <a href="{html.escape(email_report.gravatar_profile_url or '#')}" target="_blank">{html.escape(email_report.gravatar_display_name or 'View Profile')}</a>
                    </div>
                </div>
                """
            github_info = ""
            if email_report.github_user:
                github_info = f"""<div style="margin-top:8px;"><strong>Linked GitHub</strong>: <a href="{html.escape(email_report.github_profile_url or '#')}" target="_blank">@{html.escape(email_report.github_user)}</a></div>"""

            email_html = f"""
            <div class="card">
                <h2>📧 Email Intelligence</h2>
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                    <code style="font-size:1.1rem; color:var(--cyan);">{html.escape(email_report.email)}</code>
                    {mx_badge}
                </div>
                {gravatar_info}
                {github_info}
            </div>
            """

        phone_html = ""
        if phone_report and phone_report.is_valid_format:
            phone_html = f"""
            <div class="card">
                <h2>📞 Telephony Intelligence</h2>
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                    <code style="font-size:1.1rem; color:var(--cyan);">{html.escape(phone_report.cleaned_number)}</code>
                    <span class="badge pass">{html.escape(phone_report.country_hint or 'International')}</span>
                </div>
                <div style="display:flex; gap:12px; margin-top:8px;">
                    <a class="btn-dork ddg" href="{html.escape(phone_report.whatsapp_link or '#')}" target="_blank">WhatsApp Chat</a>
                    <a class="btn-dork ddg" href="{html.escape(phone_report.telegram_link or '#')}" target="_blank">Telegram Chat</a>
                </div>
            </div>
            """

        page_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DastyClaw OSINT Dossier - {html.escape(self.target_name)}</title>
    <style>
        :root {{
            --bg: #090d16;
            --card-bg: rgba(16, 24, 40, 0.75);
            --border: rgba(56, 189, 248, 0.2);
            --cyan: #38bdf8;
            --green: #4ade80;
            --red: #f87171;
            --yellow: #facc15;
            --text: #f1f5f9;
            --text-muted: #94a3b8;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            padding: 30px 20px;
            background-image: radial-gradient(circle at 50% 0%, rgba(56, 189, 248, 0.12), transparent 45%);
            min-height: 100vh;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 20px;
            margin-bottom: 25px;
            flex-wrap: wrap;
            gap: 15px;
        }}
        .logo-wrap h1 {{ font-size: 1.8rem; font-weight: 800; color: #fff; letter-spacing: -0.5px; }}
        .logo-wrap h1 span {{ color: var(--cyan); }}
        .logo-wrap p {{ font-size: 0.85rem; color: var(--text-muted); margin-top: 4px; }}
        .header-meta {{ text-align: right; font-size: 0.85rem; color: var(--text-muted); }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 25px;
            backdrop-filter: blur(10px);
        }}
        .card h2 {{
            font-size: 1.2rem;
            color: #fff;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 8px;
            border-bottom: 1px solid rgba(255,255,255,0.06);
            padding-bottom: 10px;
        }}
        .meta-grid {{ display: flex; flex-wrap: wrap; gap: 16px; }}
        .meta-item {{
            background: rgba(255, 255, 255, 0.04);
            padding: 8px 14px;
            border-radius: 8px;
            font-size: 0.9rem;
        }}
        .meta-label {{ color: var(--text-muted); font-weight: 500; }}
        .meta-val {{ color: var(--cyan); font-weight: 600; margin-left: 6px; }}
        .accounts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 15px;
        }}
        .account-card {{
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 10px;
            padding: 16px;
            transition: all 0.2s ease;
        }}
        .account-card:hover {{
            transform: translateY(-2px);
            border-color: var(--cyan);
            background: rgba(56, 189, 248, 0.05);
        }}
        .account-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }}
        .platform-badge {{
            font-size: 0.72rem;
            text-transform: uppercase;
            font-weight: 700;
            letter-spacing: 0.5px;
            padding: 2px 8px;
            border-radius: 4px;
            background: rgba(56, 189, 248, 0.15);
            color: var(--cyan);
        }}
        .latency-badge {{ font-size: 0.75rem; color: var(--text-muted); }}
        .account-name {{ font-size: 1.1rem; color: #fff; margin-bottom: 8px; font-weight: 600; }}
        .account-link {{
            color: var(--cyan);
            text-decoration: none;
            font-size: 0.85rem;
            display: inline-flex;
            align-items: center;
            gap: 4px;
            word-break: break-all;
        }}
        .account-link:hover {{ text-decoration: underline; }}
        .badge {{ padding: 4px 10px; border-radius: 6px; font-size: 0.8rem; font-weight: 600; }}
        .badge.pass {{ background: rgba(74, 222, 128, 0.15); color: var(--green); }}
        .badge.warn {{ background: rgba(250, 204, 21, 0.15); color: var(--yellow); }}
        .gravatar-box {{ display: flex; align-items: center; gap: 15px; margin-top: 10px; }}
        .gravatar-img {{ width: 50px; height: 50px; border-radius: 50%; border: 2px solid var(--cyan); }}
        .dork-card {{
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.07);
            border-radius: 10px;
            padding: 16px;
            margin-bottom: 14px;
        }}
        .dork-title {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; flex-wrap: wrap; gap: 6px; }}
        .dork-category {{ font-weight: 700; color: #fff; font-size: 0.95rem; }}
        .dork-desc {{ font-size: 0.85rem; color: var(--text-muted); }}
        .dork-query {{
            background: #040810;
            padding: 10px;
            border-radius: 6px;
            font-size: 0.85rem;
            color: #38bdf8;
            overflow-x: auto;
            margin: 10px 0;
            border: 1px solid rgba(255, 255, 255, 0.05);
        }}
        .dork-actions {{ display: flex; gap: 10px; }}
        .btn-dork {{
            padding: 6px 14px;
            border-radius: 6px;
            font-size: 0.82rem;
            font-weight: 600;
            text-decoration: none;
            display: inline-block;
            transition: opacity 0.2s;
        }}
        .btn-dork:hover {{ opacity: 0.85; }}
        .btn-dork.google {{ background: #2563eb; color: #fff; }}
        .btn-dork.ddg {{ background: #ea580c; color: #fff; }}
        footer {{ text-align: center; font-size: 0.8rem; color: var(--text-muted); margin-top: 40px; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo-wrap">
                <h1>Dasty<span>Claw</span> OSINT Dossier</h1>
                <p>Tactical Reconnaissance & Intelligence Snapshot by pajadasty</p>
            </div>
            <div class="header-meta">
                <div><strong>Target:</strong> {html.escape(self.target_name)}</div>
                <div>{html.escape(self.timestamp)}</div>
            </div>
        </header>

        {f'<div class="card"><h2>👤 Target Profile</h2><div class="meta-grid">{profile_rows}</div></div>' if profile_rows else ''}

        <div class="card">
            <h2>🎯 Discovered Digital Footprint ({len(found_accounts)} Active Accounts)</h2>
            <div class="accounts-grid">
                {accounts_html or '<p style="color:var(--text-muted);">No profiles detected on searched networks.</p>'}
            </div>
        </div>

        {email_html}
        {phone_html}

        {f'<div class="card"><h2>🔎 Tactical OSINT Search Dorks</h2>{dorks_html}</div>' if dorks_html else ''}

        <footer>
            Generated by <strong>DastyClaw</strong> v0.1.0 • Tactical Footprinting Toolkit by <strong>pajadasty</strong>
        </footer>
    </div>
</body>
</html>
"""
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(page_content)

        return out_path
