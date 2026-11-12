from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class PlatformTarget:
    name: str
    url_template: str
    category: str
    check_type: str = "status_code"  # "status_code" or "not_found_string"
    error_code: int = 404
    error_string: Optional[str] = None

    def get_url(self, username: str) -> str:
        return self.url_template.format(username=username)


PLATFORMS: List[PlatformTarget] = [
    # Developer & Tech
    PlatformTarget("GitHub", "https://github.com/{username}", "Developer", "status_code"),
    PlatformTarget("GitLab", "https://gitlab.com/{username}", "Developer", "status_code"),
    PlatformTarget("HackerNews", "https://news.ycombinator.com/user?id={username}", "Developer", "not_found_string", error_string="No such user."),
    PlatformTarget("DockerHub", "https://hub.docker.com/v2/users/{username}/", "Developer", "status_code"),
    PlatformTarget("NPM", "https://www.npmjs.com/~{username}", "Developer", "status_code"),
    PlatformTarget("PyPI", "https://pypi.org/user/{username}/", "Developer", "status_code"),
    PlatformTarget("Dev.to", "https://dev.to/{username}", "Developer", "status_code"),
    PlatformTarget("Keybase", "https://keybase.io/{username}", "Security & Crypto", "status_code"),
    PlatformTarget("Hashnode", "https://hashnode.com/@{username}", "Developer", "status_code"),
    PlatformTarget("Replit", "https://replit.com/@{username}", "Developer", "status_code"),

    # Social & Discussion
    PlatformTarget("Reddit", "https://www.reddit.com/user/{username}/about.json", "Social", "status_code"),
    PlatformTarget("Telegram", "https://t.me/{username}", "Messaging", "not_found_string", error_string="If you have <strong>Telegram</strong>, you can contact"),
    PlatformTarget("Twitter/X", "https://twitter.com/{username}", "Social", "status_code"),
    PlatformTarget("Mastodon", "https://mastodon.social/@{username}", "Social", "status_code"),
    PlatformTarget("Pinterest", "https://www.pinterest.com/{username}/", "Social", "status_code"),
    PlatformTarget("Medium", "https://medium.com/@{username}", "Blogging", "status_code"),
    PlatformTarget("Substack", "https://{username}.substack.com", "Blogging", "status_code"),
    PlatformTarget("ProductHunt", "https://www.producthunt.com/@{username}", "Product", "status_code"),
    PlatformTarget("Disqus", "https://disqus.com/by/{username}/", "Community", "status_code"),

    # Gaming & Creative
    PlatformTarget("Steam", "https://steamcommunity.com/id/{username}", "Gaming", "not_found_string", error_string="The specified profile could not be found"),
    PlatformTarget("Twitch", "https://www.twitch.tv/{username}", "Streaming", "status_code"),
    PlatformTarget("Chess.com", "https://api.chess.com/pub/player/{username}", "Gaming", "status_code"),
    PlatformTarget("SoundCloud", "https://soundcloud.com/{username}", "Music", "status_code"),
    PlatformTarget("Spotify", "https://open.spotify.com/user/{username}", "Music", "status_code"),
    PlatformTarget("Vimeo", "https://vimeo.com/{username}", "Video", "status_code"),
    PlatformTarget("Bandcamp", "https://bandcamp.com/{username}", "Music", "status_code"),
    PlatformTarget("Letterboxd", "https://letterboxd.com/{username}/", "Media", "status_code"),
    PlatformTarget("Dribbble", "https://dribbble.com/{username}", "Design", "status_code"),
    PlatformTarget("Behance", "https://www.behance.net/{username}", "Design", "status_code"),
    PlatformTarget("Flickr", "https://www.flickr.com/people/{username}/", "Photography", "status_code"),

    # Knowledge & Productivity
    PlatformTarget("Wikipedia", "https://en.wikipedia.org/wiki/User:{username}", "Knowledge", "status_code"),
    PlatformTarget("About.me", "https://about.me/{username}", "Profile", "status_code"),
    PlatformTarget("Linktree", "https://linktr.ee/{username}", "Profile", "status_code"),
    PlatformTarget("BuyMeACoffee", "https://www.buymeacoffee.com/{username}", "Creator", "status_code"),
    PlatformTarget("Patreon", "https://www.patreon.com/{username}", "Creator", "status_code"),
    PlatformTarget("Pastebin", "https://pastebin.com/u/{username}", "Developer", "status_code"),
]
