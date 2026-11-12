from dastyclaw.dork_generator import DorkGenerator
from dastyclaw.email_hunter import EmailHunter


def test_dork_generation():
    dorks = DorkGenerator.generate(
        username="pajadasty",
        real_name="Pavel Tester",
        email="test@example.com",
        location="Prague",
    )
    assert len(dorks) >= 3

    categories = [d.category for d in dorks]
    assert "Social & Professional" in categories
    assert "Username Footprint" in categories
    assert "Pastes & Dumps" in categories
    assert "Code & Git Repos" in categories

    for d in dorks:
        assert d.google_url.startswith("https://www.google.com/search?q=")
        assert d.duckduckgo_url.startswith("https://duckduckgo.com/?q=")


def test_email_hash():
    # md5 of 'test@example.com'
    # test@example.com -> 55502f40dc8b7c769880b10874abc9d0
    h = EmailHunter.hash_email("Test@Example.COM ")
    assert h == "55502f40dc8b7c769880b10874abc9d0"
