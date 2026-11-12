from dastyclaw.dork_generator import DorkGenerator
from dastyclaw.email_hunter import EmailHunter
from dastyclaw.phone_hunter import PhoneHunter


def test_dork_generation():
    dorks = DorkGenerator.generate(
        username="pajadasty",
        real_name="Pavel Tester",
        email="test@example.com",
        location="Prague",
        phone="+420123456789",
    )
    assert len(dorks) >= 4

    categories = [d.category for d in dorks]
    assert "Social & Professional" in categories
    assert "Username Footprint" in categories
    assert "Pastes & Dumps" in categories
    assert "Code & Git Repos" in categories
    assert "Phone Footprint" in categories

    for d in dorks:
        assert d.google_url.startswith("https://www.google.com/search?q=")
        assert d.duckduckgo_url.startswith("https://duckduckgo.com/?q=")


def test_email_hash():
    h = EmailHunter.hash_email("Test@Example.COM ")
    assert h == "55502f40dc8b7c769880b10874abc9d0"


def test_phone_hunter():
    res = PhoneHunter.analyze("+420 777 123 456")
    assert res.is_valid_format is True
    assert res.cleaned_number == "+420777123456"
    assert "Czech Republic" in (res.country_hint or "")
    assert "wa.me/420777123456" in res.whatsapp_link
    assert "t.me/+420777123456" in res.telegram_link

    bad = PhoneHunter.analyze("123")
    assert bad.is_valid_format is False
