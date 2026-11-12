from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class PlatformTarget:
    name: str
    url_template: str
    category: str
    check_type: str = "status_code"  # "status_code", "not_found_string", "custom"
    error_code: int = 404
    error_string: Optional[str] = None
    custom_probe: Optional[str] = None  # "instagram", "tiktok", "twitch", "pinterest", "telegram", "hashnode"

    def get_url(self, username: str) -> str:
        return self.url_template.format(username=username)


PLATFORMS: List[PlatformTarget] = [
    # Top Social & Video (with precision engine)
    PlatformTarget("Instagram", "https://www.instagram.com/{username}/", "Social", check_type="custom", custom_probe="instagram"),
    PlatformTarget("TikTok", "https://www.tiktok.com/@{username}", "Video & Social", check_type="custom", custom_probe="tiktok"),
    PlatformTarget("Twitch", "https://www.twitch.tv/{username}", "Streaming", check_type="custom", custom_probe="twitch"),
    PlatformTarget("Pinterest", "https://www.pinterest.com/{username}/", "Social", check_type="custom", custom_probe="pinterest"),
    PlatformTarget("Telegram", "https://t.me/{username}", "Messaging", check_type="custom", custom_probe="telegram"),

    # Developer & Tech
    PlatformTarget("GitHub", "https://github.com/{username}", "Developer", "status_code"),
    PlatformTarget("GitLab", "https://gitlab.com/{username}", "Developer", "status_code"),
    PlatformTarget("HackerNews", "https://news.ycombinator.com/user?id={username}", "Developer", "not_found_string", error_string="No such user."),
    PlatformTarget("DockerHub", "https://hub.docker.com/v2/users/{username}/", "Developer", "status_code"),
    PlatformTarget("NPM", "https://www.npmjs.com/~{username}", "Developer", "status_code"),
    PlatformTarget("Dev.to", "https://dev.to/{username}", "Developer", "status_code"),
    PlatformTarget("Keybase", "https://keybase.io/{username}", "Security & Crypto", "status_code"),
    PlatformTarget("Hashnode", "https://hashnode.com/@{username}", "Developer", check_type="custom", custom_probe="hashnode"),
    PlatformTarget("Replit", "https://replit.com/@{username}", "Developer", "status_code"),

    # Music & Creative
    PlatformTarget("Spotify", "https://open.spotify.com/user/{username}", "Music", "status_code"),
    PlatformTarget("SoundCloud", "https://soundcloud.com/{username}", "Music", "status_code"),
    PlatformTarget("Bandcamp", "https://bandcamp.com/{username}", "Music", "status_code"),
    PlatformTarget("Dribbble", "https://dribbble.com/{username}", "Design", "status_code"),
    PlatformTarget("Behance", "https://www.behance.net/{username}", "Design", "status_code"),
    PlatformTarget("Flickr", "https://www.flickr.com/people/{username}/", "Photography", "status_code"),
    PlatformTarget("Vimeo", "https://vimeo.com/{username}", "Video", "status_code"),

    # Blogging & Community
    PlatformTarget("Medium", "https://medium.com/@{username}", "Blogging", "status_code"),
    PlatformTarget("Substack", "https://{username}.substack.com", "Blogging", "status_code"),
    PlatformTarget("Letterboxd", "https://letterboxd.com/{username}/", "Media", "status_code"),
    PlatformTarget("Disqus", "https://disqus.com/by/{username}/", "Community", "status_code"),

    # Gaming
    PlatformTarget("Steam", "https://steamcommunity.com/id/{username}", "Gaming", "not_found_string", error_string="The specified profile could not be found"),
    PlatformTarget("Chess.com", "https://api.chess.com/pub/player/{username}", "Gaming", "status_code"),

    # Profile & Bio
    PlatformTarget("About.me", "https://about.me/{username}", "Profile", "status_code"),
    PlatformTarget("Linktree", "https://linktr.ee/{username}", "Profile", "status_code"),
    PlatformTarget("BuyMeACoffee", "https://www.buymeacoffee.com/{username}", "Creator", "status_code"),
    PlatformTarget("Patreon", "https://www.patreon.com/{username}", "Creator", "status_code"),
    PlatformTarget("Pastebin", "https://pastebin.com/u/{username}", "Developer", "status_code"),
]
