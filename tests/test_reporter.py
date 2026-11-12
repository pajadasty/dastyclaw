import json
from pathlib import Path
from dastyclaw.reporter import ReconReporter
from dastyclaw.user_hunter import HunterResult
from dastyclaw.domain_recon import DomainReconReport, MailSecurityAudit
from dastyclaw.phone_hunter import PhoneIntelResult


def test_reporter_export(tmp_path: Path):
    reporter = ReconReporter("test_target")

    results = [
        HunterResult("GitHub", "https://github.com/test", True, 200, 150, "Developer"),
        HunterResult("Twitter", "https://twitter.com/test", False, 404, 80, "Social"),
    ]

    domain_report = DomainReconReport(
        domain="test.com",
        subdomains=["api.test.com", "dev.test.com"],
        dns_records={"A": ["1.2.3.4"], "MX": ["mail.test.com"]},
        mail_security=MailSecurityAudit(has_spf=True, spf_strictness="Strict (-all)", spoofable=False),
    )

    phone_report = PhoneIntelResult(
        raw_number="+420777123456",
        cleaned_number="+420777123456",
        is_valid_format=True,
        country_hint="Czech Republic",
        whatsapp_link="https://wa.me/420777123456",
        telegram_link="https://t.me/+420777123456",
    )

    json_file = tmp_path / "report.json"
    md_file = tmp_path / "report.md"
    html_file = tmp_path / "report.html"

    reporter.export_json(json_file, hunter_results=results, domain_report=domain_report, phone_report=phone_report)
    reporter.export_markdown(md_file, hunter_results=results, domain_report=domain_report, phone_report=phone_report)
    reporter.export_html(html_file, hunter_results=results, domain_report=domain_report, phone_report=phone_report)

    assert json_file.is_file()
    assert md_file.is_file()
    assert html_file.is_file()

    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["target"] == "test_target"
    assert data["username_intel"]["total_found"] == 1
    assert data["domain_intel"]["subdomains_count"] == 2
    assert data["phone_intel"]["country"] == "Czech Republic"

    with open(md_file, "r", encoding="utf-8") as f:
        md_text = f.read()
    assert "OSINT Reconnaissance Dossier" in md_text
    assert "https://github.com/test" in md_text
    assert "api.test.com" in md_text
    assert "Telephony Intelligence" in md_text

    with open(html_file, "r", encoding="utf-8") as f:
        html_text = f.read()
    assert "DastyClaw OSINT Dossier" in html_text
    assert "GitHub" in html_text
    assert "Czech Republic" in html_text
