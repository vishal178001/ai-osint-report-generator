from unittest.mock import patch, Mock

from enrichment.providers.abuseipdb_provider import AbuseIPDBProvider


def test_provider_not_configured():
    provider = AbuseIPDBProvider()

    provider.api_key = None

    result = provider.check_ip("8.8.8.8")

    assert result["provider"] == "AbuseIPDB"
    assert result["ip"] == "8.8.8.8"
    assert result["status"] == "not_configured"


@patch("enrichment.providers.abuseipdb_provider.requests.get")
def test_provider_success(mock_get):
    mock_response = Mock()

    mock_response.json.return_value = {
        "data": {
            "ipAddress": "8.8.8.8",
            "abuseConfidenceScore": 10,
            "countryCode": "US",
            "totalReports": 2,
        }
    }

    mock_response.raise_for_status.return_value = None
    mock_get.return_value = mock_response

    provider = AbuseIPDBProvider(api_key="fake-test-key")
