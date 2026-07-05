from enrichment.threat_intelligence import (
    analyze_ip,
    enrich_threat_intelligence,
)


def test_public_ip():
    result = analyze_ip("8.8.8.8")

    assert result["valid"] is True
    assert result["risk_level"] == "Public"


def test_private_ip():
    result = analyze_ip("192.168.1.10")

    assert result["valid"] is True
    assert result["is_private"] is True
    assert result["risk_level"] == "Internal"


def test_invalid_ip():
    result = analyze_ip("not-an-ip")

    assert result["valid"] is False
    assert result["risk_level"] == "Invalid"


def test_threat_intelligence_enrichment():
    report_data = {
        "domain_intelligence": {
            "ip_addresses": [
                "8.8.8.8",
                "192.168.1.10",
            ]
        }
    }

    result = enrich_threat_intelligence(report_data)

    assert result["total_ips_analyzed"] == 2
    assert len(result["ip_analysis"]) == 2

from unittest.mock import patch


@patch(
    "enrichment.threat_intelligence.AbuseIPDBProvider.check_ip"
)
def test_provider_integration(mock_check_ip):
    mock_check_ip.return_value = {
        "provider": "AbuseIPDB",
        "ip": "8.8.8.8",
        "status": "success",
        "abuse_confidence_score": 10,
    }

    report_data = {
        "domain_intelligence": {
            "ip_addresses": ["8.8.8.8"]
        }
    }

    result = enrich_threat_intelligence(report_data)

    assert "provider_results" in result
    assert len(result["provider_results"]) == 1
    assert result["provider_results"][0]["provider"] == "AbuseIPDB"
    assert result["provider_results"][0]["status"] == "success"

    mock_check_ip.assert_called_once_with("8.8.8.8")
