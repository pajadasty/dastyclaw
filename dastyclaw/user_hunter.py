from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Callable, List, Optional
import httpx

from dastyclaw.targets import PLATFORMS, PlatformTarget

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"


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
                headers = {"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"}
                resp = await client.get(url, headers=headers, follow_redirects=True)
                status_code = resp.status_code
                elapsed_ms = int((time.perf_counter() - start) * 1000)

                if target.check_type == "status_code":
                    if status_code in (200, 201):
                        found = True
                    elif status_code in (404, 410, 400):
                        found = False
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

        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            tasks = [
                self._check_platform(client, t, username, on_result)
                for t in active_targets
            ]
            results = await asyncio.gather(*tasks)

        return sorted(results, key=lambda r: (not r.found, r.platform))
