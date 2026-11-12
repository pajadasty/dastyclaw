import json
from pathlib import Path
from reconclaw.reporter import ReconReporter
from reconclaw.user_hunter import HunterResult
from reconclaw.domain_recon import DomainReconReport, MailSecurityAudit


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

    json_file = tmp_path / "report.json"
    md_file = tmp_path / "report.md"

    reporter.export_json(json_file, hunter_results=results, domain_report=domain_report)
    reporter.export_markdown(md_file, hunter_results=results, domain_report=domain_report)

    assert json_file.is_file()
    assert md_file.is_file()

    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["target"] == "test_target"
    assert data["username_intel"]["total_found"] == 1
    assert data["domain_intel"]["subdomains_count"] == 2

    with open(md_file, "r", encoding="utf-8") as f:
        md_text = f.read()
    assert "OSINT Reconnaissance Dossier" in md_text
    assert "https://github.com/test" in md_text
    assert "api.test.com" in md_text
