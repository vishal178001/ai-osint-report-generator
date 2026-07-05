from ai.security_analyzer import analyze_security


def test_security_analyzer():
    report_data = {
        "http": {
            "security_headers": {
                "Strict-Transport-Security": "Missing",
                "Content-Security-Policy": "Missing",
                "X-Frame-Options": "Present",
                "X-Content-Type-Options": "Present",
                "Referrer-Policy": "Present",
                "Permissions-Policy": "Present"
            }
        },
        "ssl": {
            "days_remaining": 10
        },
        "dns": {
            "TXT": []
        },
        "subdomains": {
            "count": 25
        }
    }

    result = analyze_security(report_data)

    assert result["total_findings"] == 6

    assert result["severity_summary"]["High"] == 1
    assert result["severity_summary"]["Medium"] == 4
    assert result["severity_summary"]["Info"] == 1

    assert len(result["findings"]) == 6

    assert result["risk_score"] == 47
    assert result["risk_rating"] == "Medium"

from ai.llm_analyzer import generate_ai_analysis


def test_ai_analysis_recommends_missing_email_security():
    report_data = {
        "security_analysis": {
            "findings": [
                {
                    "severity": "Medium",
                    "recommendation": "Review security configuration."
                }
            ],
            "risk_score": 40,
            "risk_rating": "Medium",
            "severity_summary": {
                "Critical": 0,
                "High": 0,
                "Medium": 1,
                "Low": 0,
                "Info": 0,
            },
        },
        "domain_intelligence": {
            "email_security": {
                "spf_detected": False,
                "dmarc_detected": False,
            },
            "mail_providers": [],
            "nameservers": ["ns1.example.com"],
            "ip_addresses": ["192.0.2.1"],
        },
    }

    result = generate_ai_analysis(report_data)

    actions = result["priority_actions"]

    assert any("SPF" in action for action in actions)
    assert any("DMARC" in action for action in actions)

def test_malicious_ip_creates_high_finding():
    report_data = {
        "http": {
            "security_headers": {}
        },
        "threat_intelligence": {
            "provider_results": [
                {
                    "provider": "AbuseIPDB",
                    "ip": "203.0.113.10",
                    "status": "success",
                    "abuse_confidence_score": 90,
                }
            ]
        }
    }

    result = analyze_security(report_data)

    threat_findings = [
        finding
        for finding in result["findings"]
        if finding["category"] == "Threat Intelligence"
    ]

    assert len(threat_findings) == 1
    assert threat_findings[0]["severity"] == "High"
    assert threat_findings[0]["finding"] == "High-Risk Malicious IP Detected"
