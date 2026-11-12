from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
import httpx

CLOUDFLARE_DOH_URL = "https://cloudflare-dns.com/dns-query"


@dataclass
class MailSecurityAudit:
    has_spf: bool = False
    spf_record: Optional[str] = None
    spf_strictness: str = "Missing"  # "Strict (-all)", "Softfail (~all)", "Permissive (+all)", "Missing"
    has_dmarc: bool = False
    dmarc_record: Optional[str] = None
    dmarc_policy: str = "Missing"  # "reject", "quarantine", "none", "Missing"
    spoofable: bool = True
    summary: str = ""


@dataclass
class DomainReconReport:
    domain: str
    subdomains: List[str] = field(default_factory=list)
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    mail_security: Optional[MailSecurityAudit] = None


class DomainRecon:
    def __init__(self, timeout_sec: float = 8.0):
        self.timeout = httpx.Timeout(timeout_sec, connect=4.0)

    async def _query_doh(self, client: httpx.AsyncClient, name: str, record_type: str) -> List[str]:
        """Query DNS records over HTTPS via Cloudflare 1.1.1.1 JSON DoH API."""
        try:
            resp = await client.get(
                CLOUDFLARE_DOH_URL,
                params={"name": name, "type": record_type},
                headers={"Accept": "application/dns-json"},
            )
            if resp.status_code == 200:
                data = resp.json()
                answers = data.get("Answer", [])
                results = []
                for ans in answers:
                    val = str(ans.get("data", "")).strip('"')
                    if val:
                        results.append(val)
                return results
        except Exception:
            pass
        return []

    async def fetch_subdomains_crtsh(self, client: httpx.AsyncClient, domain: str) -> List[str]:
        """Enumerate subdomains via public Certificate Transparency logs (crt.sh)."""
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        subdomains: Set[str] = set()

        try:
            resp = await client.get(url, headers={"User-Agent": "DastyClaw/1.0"})
            if resp.status_code == 200:
                entries = resp.json()
                for entry in entries:
                    name_val = entry.get("name_value", "")
                    for raw in name_val.split("\n"):
                        clean = raw.strip().lower()
                        if clean.startswith("*."):
                            clean = clean[2:]
                        if clean.endswith(domain) and clean != domain:
                            subdomains.add(clean)
        except Exception:
            pass

        return sorted(list(subdomains))

    def audit_mail_security(self, txt_records: List[str], dmarc_records: List[str]) -> MailSecurityAudit:
        audit = MailSecurityAudit()

        # Check SPF
        for r in txt_records:
            if r.startswith("v=spf1"):
                audit.has_spf = True
                audit.spf_record = r
                if "-all" in r:
                    audit.spf_strictness = "Strict (-all)"
                elif "~all" in r:
                    audit.spf_strictness = "Softfail (~all)"
                elif "+all" in r:
                    audit.spf_strictness = "Permissive (+all)"
                else:
                    audit.spf_strictness = "Neutral"
                break

        # Check DMARC
        for r in dmarc_records:
            if "v=DMARC1" in r:
                audit.has_dmarc = True
                audit.dmarc_record = r
                policy_match = re.search(r"p=(reject|quarantine|none)", r, re.IGNORECASE)
                if policy_match:
                    audit.dmarc_policy = policy_match.group(1).lower()
                break

        # Determine spoofability
        if not audit.has_spf and not audit.has_dmarc:
            audit.spoofable = True
            audit.summary = "High Risk: No SPF or DMARC records found. Anyone can forge emails from this domain."
        elif audit.dmarc_policy == "reject" or audit.spf_strictness == "Strict (-all)":
            audit.spoofable = False
            audit.summary = "Secure: Strong DMARC reject or strict SPF policy blocks email spoofing."
        elif audit.dmarc_policy == "none":
            audit.spoofable = True
            audit.summary = "Moderate Risk: DMARC is in monitoring mode (p=none); spoofed emails may still be delivered."
        else:
            audit.spoofable = True
            audit.summary = "Partial Protection: Basic records present, but policy allows softfail delivery."

        return audit

    async def scan_domain(self, domain: str) -> DomainReconReport:
        clean_domain = domain.lower().replace("https://", "").replace("http://", "").split("/")[0].strip()

        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            # Query DNS records concurrently
            a_records_task = self._query_doh(client, clean_domain, "A")
            aaaa_records_task = self._query_doh(client, clean_domain, "AAAA")
            mx_records_task = self._query_doh(client, clean_domain, "MX")
            txt_records_task = self._query_doh(client, clean_domain, "TXT")
            dmarc_records_task = self._query_doh(client, f"_dmarc.{clean_domain}", "TXT")
            subdomains_task = self.fetch_subdomains_crtsh(client, clean_domain)

            a_recs, aaaa_recs, mx_recs, txt_recs, dmarc_recs, subdomains = await asyncio.gather(
                a_records_task,
                aaaa_records_task,
                mx_records_task,
                txt_records_task,
                dmarc_records_task,
                subdomains_task,
            )

        dns_records: Dict[str, List[str]] = {
            "A": a_recs,
            "AAAA": aaaa_recs,
            "MX": mx_recs,
            "TXT": txt_recs,
        }

        mail_audit = self.audit_mail_security(txt_recs, dmarc_recs)

        return DomainReconReport(
            domain=clean_domain,
            subdomains=subdomains,
            dns_records=dns_records,
            mail_security=mail_audit,
        )
