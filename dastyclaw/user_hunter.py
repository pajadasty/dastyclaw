from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass
from typing import Callable, List, Optional
import httpx

from dastyclaw.targets import PLATFORMS, PlatformTarget

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


@dataclass
class HunterResult:
    platform: str
    url: str
    found: bool
    status_code: int
    elapsed_ms: int
    category: str


class UserHunter:
    def __init__(self, concurrency: int = 25, timeout_sec: float = 6.0):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.timeout = httpx.Timeout(timeout_sec, connect=4.0)

    async def _probe_custom(self, client: httpx.AsyncClient, probe: str, username: str, url: str) -> tuple[bool, int]:
        clean_user = username.strip().lower()

        if probe == "instagram":
            resp = await client.get(url, headers={"User-Agent": GOOGLEBOT_UA})
            if resp.status_code == 200:
                og_match = re.search(r'<meta property="og:title" content="([^"]+)"', resp.text)
                title_match = re.search(r'<title>([^<]+)</title>', resp.text)
                header_text = ((og_match.group(1) if og_match else "") + " " + (title_match.group(1) if title_match else "")).lower()
                has_user = f"@{clean_user}" in header_text or f"&#064;{clean_user}" in header_text or f"({clean_user})" in header_text
                return has_user, resp.status_code
            return False, resp.status_code

        elif probe == "tiktok":
            resp = await client.get(url, headers={"User-Agent": USER_AGENT})
            if resp.status_code == 200:
                m = re.search(r'<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>(.*?)</script>', resp.text)
                if m:
                    try:
                        data = json.loads(m.group(1))
                        scope = data.get("__DEFAULT_SCOPE__", {})
                        user_detail = scope.get("webapp.user-detail", {})
                        status_code = user_detail.get("statusCode")
                        user_info = user_detail.get("userInfo", {})
                        return status_code == 0 and bool(user_info), resp.status_code
                    except Exception:
                        pass
            return False, resp.status_code

        elif probe == "twitch":
            payload = {
                "query": "query($login: String!) { user(login: $login) { id login } }",
                "variables": {"login": clean_user},
            }
            resp = await client.post(
                "https://gql.twitch.tv/gql",
                json=payload,
                headers={"Client-ID": "kimne78kx3ncx6brgo4mv6wki5h1ko", "User-Agent": USER_AGENT},
            )
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    is_user = data.get("data", {}).get("user") is not None
                    return is_user, resp.status_code
                except Exception:
                    pass
            return False, resp.status_code

        elif probe == "pinterest":
            resp = await client.get(url, headers={"User-Agent": USER_AGENT})
            if resp.status_code == 200:
                has_og = "og:title" in resp.text
                has_title = "Profile | Pinterest" in resp.text or f"({clean_user})" in resp.text.lower()
                return has_og and has_title, resp.status_code
            return False, resp.status_code

        elif probe == "telegram":
            resp = await client.get(url, headers={"User-Agent": USER_AGENT})
            if resp.status_code == 200:
                has_extra = '<div class="tgme_page_extra">' in resp.text
                return has_extra, resp.status_code
            return False, resp.status_code

        elif probe == "hashnode":
            resp = await client.get(url, headers={"User-Agent": USER_AGENT})
            if resp.status_code == 200:
                not_found = "User not found" in resp.text or "404" in resp.text
                return not not_found, resp.status_code
            return False, resp.status_code

        return False, 0

    async def _check_platform(
        self,
        client: httpx.AsyncClient,
        target: PlatformTarget,
        username: str,
        on_result: Optional[Callable[[HunterResult], None]] = None,
    ) -> HunterResult:
        url = target.get_url(username)
        start = time.perf_counter()
        found = False
        status_code = 0

        async with self.semaphore:
            try:
                if target.check_type == "custom" and target.custom_probe:
                    found, status_code = await self._probe_custom(client, target.custom_probe, username, url)
                else:
                    headers = {"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"}
                    resp = await client.get(url, headers=headers, follow_redirects=True)
                    status_code = resp.status_code

                    if target.check_type == "status_code":
                        if status_code in (200, 201):
                            found = True
                        else:
                            found = False

                    elif target.check_type == "not_found_string":
                        if status_code == 200:
                            if target.error_string and target.error_string in resp.text:
                                found = False
                            else:
                                found = True
                        else:
                            found = False

                elapsed_ms = int((time.perf_counter() - start) * 1000)

            except httpx.RequestError:
                elapsed_ms = int((time.perf_counter() - start) * 1000)
                status_code = 0
                found = False

        result = HunterResult(
            platform=target.name,
            url=url,
            found=found,
            status_code=status_code,
            elapsed_ms=elapsed_ms,
            category=target.category,
        )

        if on_result:
            on_result(result)

        return result

    async def hunt(
        self,
        username: str,
        targets: Optional[List[PlatformTarget]] = None,
        on_result: Optional[Callable[[HunterResult], None]] = None,
    ) -> List[HunterResult]:
        active_targets = targets or PLATFORMS

        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, verify=False) as client:
            tasks = [
                self._check_platform(client, t, username, on_result)
                for t in active_targets
            ]
            results = await asyncio.gather(*tasks)

        return sorted(results, key=lambda r: (not r.found, r.platform))
