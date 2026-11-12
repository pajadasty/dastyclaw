from dastyclaw.targets import PLATFORMS, PlatformTarget


def test_platforms_integrity():
    assert len(PLATFORMS) >= 30
    for p in PLATFORMS:
        assert isinstance(p, PlatformTarget)
        assert "{username}" in p.url_template
        url = p.get_url("johndoe")
        assert "johndoe" in url
        assert url.startswith("https://")
