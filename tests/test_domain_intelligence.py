from enrichment.domain_intelligence import enrich_domain_intelligence


def test_domain_intelligence():
    sample_data = {
        "dns": {
            "TXT": [
                "v=spf1 include:_spf.example.com -all",
                "v=DMARC1; p=reject"
            ],
            "MX": [
                "10 mail.example.com"
            ],
            "NS": [
                "ns1.example.com",
                "ns2.example.com"
            ],
            "A": [
                "192.0.2.10"
            ]
        }
    }

    result = enrich_domain_intelligence(sample_data)

    assert result["email_security"]["spf_detected"] is True
    assert result["email_security"]["dmarc_detected"] is True

    assert "10 mail.example.com" in result["mail_providers"]
    assert "ns1.example.com" in result["nameservers"]
    assert "192.0.2.10" in result["ip_addresses"]
