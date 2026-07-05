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

