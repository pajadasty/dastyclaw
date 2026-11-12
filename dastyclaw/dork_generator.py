from __future__ import annotations

import urllib.parse
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class OsintDork:
    category: str
    description: str
    query: str
    google_url: str
    duckduckgo_url: str


class DorkGenerator:
    """Generates tactical OSINT search engine dorks for deep target footprinting."""

    @staticmethod
    def _build_url(query: str, engine: str = "google") -> str:
        encoded = urllib.parse.quote_plus(query)
        if engine == "google":
            return f"https://www.google.com/search?q={encoded}"
        elif engine == "duckduckgo":
            return f"https://duckduckgo.com/?q={encoded}"
        return f"https://www.google.com/search?q={encoded}"

    @classmethod
    def generate(
        cls,
        username: Optional[str] = None,
        real_name: Optional[str] = None,
        email: Optional[str] = None,
        location: Optional[str] = None,
        phone: Optional[str] = None,
    ) -> List[OsintDork]:
        dorks: List[OsintDork] = []

        # 1. Social Profiles & Professional Networks
        if real_name:
            loc_filter = f' "{location}"' if location else ""
            q = f'site:linkedin.com/in | site:facebook.com | site:instagram.com | site:twitter.com "{real_name}"{loc_filter}'
            dorks.append(OsintDork(
                category="Social & Professional",
                description="Locate social media and LinkedIn profiles matching real name",
                query=q,
                google_url=cls._build_url(q, "google"),
                duckduckgo_url=cls._build_url(q, "duckduckgo"),
            ))

        if username:
            q = f'site:reddit.com | site:medium.com | site:dev.to | site:t.me "{username}"'
            dorks.append(OsintDork(
                category="Username Footprint",
                description="Find forum posts, developer articles, and community mentions",
                query=q,
                google_url=cls._build_url(q, "google"),
                duckduckgo_url=cls._build_url(q, "duckduckgo"),
            ))

        # 2. Public Documents & Resumes
        target_term = real_name or username
        if target_term:
            q = f'"{target_term}" filetype:pdf | filetype:docx (cv OR resume OR "curriculum vitae")'
            dorks.append(OsintDork(
                category="Documents & Resumes",
                description="Discover publicly exposed resumes, presentations, and documents",
                query=q,
                google_url=cls._build_url(q, "google"),
                duckduckgo_url=cls._build_url(q, "duckduckgo"),
            ))

        # 3. Pastebin & Leak Mentions
        search_terms = []
        if email:
            search_terms.append(f'"{email}"')
        if username:
            search_terms.append(f'"{username}"')
        if search_terms:
            terms_q = " OR ".join(search_terms)
            q = f'site:pastebin.com | site:ghostbin.co | site:throwbin.io | site:rentry.co ({terms_q})'
            dorks.append(OsintDork(
                category="Pastes & Dumps",
                description="Search for credentials, dump files, and mentions on paste sites",
                query=q,
                google_url=cls._build_url(q, "google"),
                duckduckgo_url=cls._build_url(q, "duckduckgo"),
            ))

        # 4. Code & Git Repositories
        if email:
            q = f'site:github.com | site:gitlab.com | site:bitbucket.org "{email}"'
            dorks.append(OsintDork(
                category="Code & Git Repos",
                description="Search for commits, exposed configs, and issue comments",
                query=q,
                google_url=cls._build_url(q, "google"),
                duckduckgo_url=cls._build_url(q, "duckduckgo"),
            ))

        # 5. Phone Number Intelligence
        if phone:
            clean_digits = "".join(c for c in phone if c.isdigit())
            q = f'"{phone}" | "{clean_digits}" site:sync.me | site:truecaller.com | site:facebook.com'
            dorks.append(OsintDork(
                category="Phone Footprint",
                description="Search for directory registrations, reverse phone listings, and contacts",
                query=q,
                google_url=cls._build_url(q, "google"),
                duckduckgo_url=cls._build_url(q, "duckduckgo"),
            ))

        return dorks
