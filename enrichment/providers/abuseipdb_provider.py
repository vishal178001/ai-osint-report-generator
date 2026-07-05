import os
import requests

from enrichment.providers.base_provider import ThreatIntelligenceProvider


class AbuseIPDBProvider(ThreatIntelligenceProvider):

    API_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key=None, timeout=10):
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")
        self.timeout = timeout

    def is_configured(self):
        return bool(self.api_key)

    def check_ip(self, ip_address):
        if not self.is_configured():
            return {
                "provider": "AbuseIPDB",
                "ip": ip_address,
                "status": "not_configured",
                "error": None,
            }

        headers = {
            "Accept": "application/json",
            "Key": self.api_key,
        }

        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90,
        }

        try:
            response = requests.get(
                self.API_URL,
                headers=headers,
                params=params,
                timeout=self.timeout,
            )

            if response.status_code == 429:
                return {
                    "provider": "AbuseIPDB",
                    "ip": ip_address,
                    "status": "rate_limited",
                    "error": "API rate limit reached",
                }

            response.raise_for_status()

            data = response.json().get("data", {})

            return {
                "provider": "AbuseIPDB",
                "ip": ip_address,
                "status": "success",
                "abuse_confidence_score": data.get(
                    "abuseConfidenceScore", 0
                ),
                "total_reports": data.get("totalReports", 0),
                "country_code": data.get("countryCode"),
                "usage_type": data.get("usageType"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "last_reported_at": data.get("lastReportedAt"),
                "error": None,
            }

        except requests.Timeout:
            return {
                "provider": "AbuseIPDB",
                "ip": ip_address,
                "status": "timeout",
                "error": "Request timed out",
            }

        except requests.RequestException as exc:
            return {
                "provider": "AbuseIPDB",
                "ip": ip_address,
                "status": "error",
                "error": str(exc),
            }

        except ValueError:
            return {
                "provider": "AbuseIPDB",
                "ip": ip_address,
                "status": "error",
                "error": "Invalid JSON response",
            }
