from reconclaw.domain_recon import DomainRecon


def test_mail_security_audit_secure():
    recon = DomainRecon()
    txt_records = ["v=spf1 include:_spf.google.com -all"]
    dmarc_records = ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]

    audit = recon.audit_mail_security(txt_records, dmarc_records)
    assert audit.has_spf is True
    assert audit.spf_strictness == "Strict (-all)"
    assert audit.has_dmarc is True
    assert audit.dmarc_policy == "reject"
    assert audit.spoofable is False


def test_mail_security_audit_vulnerable():
    recon = DomainRecon()
    txt_records = []
    dmarc_records = []

    audit = recon.audit_mail_security(txt_records, dmarc_records)
    assert audit.has_spf is False
    assert audit.has_dmarc is False
    assert audit.spoofable is True
    assert "High Risk" in audit.summary


def test_mail_security_softfail_dmarc_none():
    recon = DomainRecon()
    txt_records = ["v=spf1 include:_spf.example.com ~all"]
    dmarc_records = ["v=DMARC1; p=none;"]

    audit = recon.audit_mail_security(txt_records, dmarc_records)
    assert audit.spf_strictness == "Softfail (~all)"
    assert audit.dmarc_policy == "none"
    assert audit.spoofable is True
