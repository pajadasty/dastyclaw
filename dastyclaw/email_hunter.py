from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Optional
import httpx


@dataclass
class EmailFootprintResult:
    email: str
    is_valid_format: bool
    domain: str
    gravatar_found: bool = False
    gravatar_profile_url: Optional[str] = None
    gravatar_username: Optional[str] = None
    gravatar_display_name: Optional[str] = None
    gravatar_avatar_url: Optional[str] = None
    github_user: Optional[str] = None
    github_profile_url: Optional[str] = None
    mx_valid: bool = False
    notes: str = ""


EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


class EmailHunter:
    def __init__(self, timeout_sec: float = 6.0):
        self.timeout = httpx.Timeout(timeout_sec, connect=4.0)

    @staticmethod
    def hash_email(email: str) -> str:
        """Returns md5 hex digest of lowercase trimmed email (Gravatar standard)."""
        return hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()

    async def check_gravatar(self, client: httpx.AsyncClient, email_hash: str) -> dict:
        """Query public Gravatar profile API."""
        url = f"https://en.gravatar.com/{email_hash}.json"
        try:
            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                data = resp.json()
                entries = data.get("entry", [])
                if entries:
                    entry = entries[0]
                    return {
                        "found": True,
                        "profile_url": entry.get("profileUrl"),
                        "preferred_username": entry.get("preferredUsername"),
                        "display_name": entry.get("displayName"),
                        "avatar_url": entry.get("thumbnailUrl"),
                    }
        except Exception:
            pass
        return {"found": False}

    async def check_github_email(self, client: httpx.AsyncClient, email: str) -> dict:
        """Search GitHub public API for users matching this public email."""
        url = f"https://api.github.com/search/users?q={email}+in:email"
        try:
            resp = await client.get(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Accept": "application/vnd.github.v3+json",
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                items = data.get("items", [])
                if items:
                    user = items[0]
                    return {
                        "found": True,
                        "username": user.get("login"),
                        "url": user.get("html_url"),
                    }
        except Exception:
            pass
        return {"found": False}

    async def check_mx_domain(self, client: httpx.AsyncClient, domain: str) -> bool:
        """Check if email domain has valid MX records via Cloudflare DoH."""
        url = "https://cloudflare-dns.com/dns-query"
        try:
            resp = await client.get(
                url,
                params={"name": domain, "type": "MX"},
                headers={"Accept": "application/dns-json"},
            )
            if resp.status_code == 200:
                data = resp.json()
                return len(data.get("Answer", [])) > 0
        except Exception:
            pass
        return False

    async def hunt(self, email: str) -> EmailFootprintResult:
        clean_email = email.strip().lower()
        if not EMAIL_REGEX.match(clean_email):
            return EmailFootprintResult(
                email=email,
                is_valid_format=False,
                domain="",
                notes="Invalid email syntax format.",
            )

        domain = clean_email.split("@")[1]
        email_hash = self.hash_email(clean_email)

        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, verify=False) as client:
            gravatar_data = await self.check_gravatar(client, email_hash)
            github_data = await self.check_github_email(client, clean_email)
            mx_valid = await self.check_mx_domain(client, domain)

        return EmailFootprintResult(
            email=clean_email,
            is_valid_format=True,
            domain=domain,
            gravatar_found=gravatar_data.get("found", False),
            gravatar_profile_url=gravatar_data.get("profile_url"),
            gravatar_username=gravatar_data.get("preferred_username"),
            gravatar_display_name=gravatar_data.get("display_name"),
            gravatar_avatar_url=gravatar_data.get("avatar_url"),
            github_user=github_data.get("username"),
            github_profile_url=github_data.get("url"),
            mx_valid=mx_valid,
            notes="Active mail server verified via MX." if mx_valid else "MX records not detected.",
        )
