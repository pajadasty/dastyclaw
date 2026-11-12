from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional
import httpx


@dataclass
class HeaderCheckResult:
    header_name: str
    present: bool
    value: Optional[str] = None
    severity: str = "Info"  # "High", "Medium", "Low", "Info"
    description: str = ""
    recommendation: str = ""


@dataclass
class SecurityHeadersReport:
    url: str
    score: int  # 0 to 100
    grade: str  # A+, A, B, C, D, F
    checks: List[HeaderCheckResult] = field(default_factory=list)
    server_tokens: Optional[str] = None
    powered_by: Optional[str] = None


class SecurityHeadersAuditor:
    def __init__(self, timeout_sec: float = 6.0):
        self.timeout = httpx.Timeout(timeout_sec, connect=4.0)

    async def audit(self, target: str) -> SecurityHeadersReport:
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"

        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, verify=False) as client:
            resp = await client.get(url, headers={"User-Agent": "ReconClaw/1.0"})
            headers = {k.lower(): v for k, v in resp.headers.items()}

        checks: List[HeaderCheckResult] = []
        score = 100

        # 1. HSTS
        hsts_val = headers.get("strict-transport-security")
        if hsts_val:
            checks.append(HeaderCheckResult(
                header_name="Strict-Transport-Security",
                present=True,
                value=hsts_val,
                severity="Info",
                description="Enforces HTTPS encryption and prevents downgrade/SSL-stripping attacks.",
            ))
        else:
            score -= 25
            checks.append(HeaderCheckResult(
                header_name="Strict-Transport-Security",
                present=False,
                severity="High",
                description="HSTS is missing.",
                recommendation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
            ))

        # 2. Content-Security-Policy (CSP)
        csp_val = headers.get("content-security-policy")
        if csp_val:
            checks.append(HeaderCheckResult(
                header_name="Content-Security-Policy",
                present=True,
                value=csp_val[:80] + ("..." if len(csp_val) > 80 else ""),
                severity="Info",
                description="Restricts authorized sources of scripts and resources to mitigate XSS.",
            ))
        else:
            score -= 25
            checks.append(HeaderCheckResult(
                header_name="Content-Security-Policy",
                present=False,
                severity="High",
                description="CSP is missing. Vulnerable to cross-site scripting (XSS) and data injection.",
                recommendation="Define a robust CSP policy defining trusted script-src, style-src, and default-src.",
            ))

        # 3. X-Frame-Options
        xfo_val = headers.get("x-frame-options")
        if xfo_val:
            checks.append(HeaderCheckResult(
                header_name="X-Frame-Options",
                present=True,
                value=xfo_val,
                severity="Info",
                description="Controls whether site can be embedded in iframe to prevent Clickjacking.",
            ))
        else:
            score -= 15
            checks.append(HeaderCheckResult(
                header_name="X-Frame-Options",
                present=False,
                severity="Medium",
                description="Missing clickjacking protection header.",
                recommendation="Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'.",
            ))

        # 4. X-Content-Type-Options
        xcto_val = headers.get("x-content-type-options")
        if xcto_val:
            checks.append(HeaderCheckResult(
                header_name="X-Content-Type-Options",
                present=True,
                value=xcto_val,
                severity="Info",
                description="Prevents MIME-sniffing security risks.",
            ))
        else:
            score -= 10
            checks.append(HeaderCheckResult(
                header_name="X-Content-Type-Options",
                present=False,
                severity="Low",
                description="Missing MIME sniffing protection.",
                recommendation="Add 'X-Content-Type-Options: nosniff'.",
            ))

        # 5. Referrer-Policy
        ref_val = headers.get("referrer-policy")
        if ref_val:
            checks.append(HeaderCheckResult(
                header_name="Referrer-Policy",
                present=True,
                value=ref_val,
                severity="Info",
                description="Controls how much referrer information is sent with requests.",
            ))
        else:
            score -= 10
            checks.append(HeaderCheckResult(
                header_name="Referrer-Policy",
                present=False,
                severity="Low",
                description="Missing referrer policy.",
                recommendation="Add 'Referrer-Policy: strict-origin-when-cross-origin'.",
            ))

        # 6. Permissions-Policy
        perm_val = headers.get("permissions-policy")
        if perm_val:
            checks.append(HeaderCheckResult(
                header_name="Permissions-Policy",
                present=True,
                value=perm_val,
                severity="Info",
                description="Restricts access to browser features (camera, microphone, geolocation).",
            ))
        else:
            score -= 10
            checks.append(HeaderCheckResult(
                header_name="Permissions-Policy",
                present=False,
                severity="Low",
                description="Missing feature permissions policy.",
                recommendation="Add 'Permissions-Policy: geolocation=(), microphone=(), camera=()'.",
            ))

        # Information disclosure leaks
        server_tokens = headers.get("server")
        powered_by = headers.get("x-powered-by")
        if server_tokens or powered_by:
            score -= 5

        # Compute letter grade
        score = max(0, min(100, score))
        if score >= 90:
            grade = "A+" if score == 100 else "A"
        elif score >= 75:
            grade = "B"
        elif score >= 60:
            grade = "C"
        elif score >= 40:
            grade = "D"
        else:
            grade = "F"

        return SecurityHeadersReport(
            url=url,
            score=score,
            grade=grade,
            checks=checks,
            server_tokens=server_tokens,
            powered_by=powered_by,
        )
