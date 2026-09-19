from reports.report_generator import generate_markdown_report


def test_report_contains_collection_status(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    (tmp_path / "reports").mkdir()

    report_data = {
        "target": "example.com",
        "collector_status": {
            "dns": "success",
            "whois": "success",
            "theharvester": "failed",
            "http": "success",
            "ssl": "success",
            "subdomains": "success",
            "technologies": "success"
        },
        "security_analysis": {
            "findings": []
        }
    }

    report_file = generate_markdown_report(report_data)

    with open(report_file, "r") as file:
        content = file.read()

    assert "## Collection Status" in content
    assert "dns: success" in content
    assert "theharvester: failed" in content


def test_report_contains_domain_intelligence(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    (tmp_path / "reports").mkdir()

    report_data = {
        "target": "example.com",
        "scan_start": "2026-07-05T20:00:00",
        "scan_end": "2026-07-05T20:01:00",
        "scan_duration_seconds": 60,
        "collector_status": {},
        "security_analysis": {
            "total_findings": 0,
            "risk_score": 0,
            "risk_rating": "Low",
            "severity_summary": {
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0,
                "Info": 0
            },
            "findings": []
        },
        "domain_intelligence": {
            "email_security": {
                "spf_detected": True,
                "dmarc_detected": False
            },
            "mail_providers": ["mail.example.com"],
            "nameservers": ["ns1.example.com"],
            "ip_addresses": ["93.184.216.34"]
        },
        "ai_analysis": {}
    }

    report_file = generate_markdown_report(report_data)

    with open(report_file, "r") as file:
        content = file.read()

    assert "## Domain Intelligence" in content
    assert "SPF Detected: True" in content
    assert "DMARC Detected: False" in content
    assert "mail.example.com" in content
    assert "ns1.example.com" in content
    assert "93.184.216.34" in content


def test_report_contains_threat_intelligence(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    (tmp_path / "reports").mkdir()

    report_data = {
        "target": "example.com",
        "collector_status": {},
        "security_analysis": {
            "total_findings": 0,
            "risk_score": 0,
            "risk_rating": "Informational",
            "severity_summary": {
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0,
                "Info": 0
            },
            "findings": []
        },
        "domain_intelligence": {
            "email_security": {
                "spf_detected": True,
                "dmarc_detected": False
            },
            "mail_providers": [],
            "nameservers": [],
            "ip_addresses": ["8.8.8.8"]
        },
        "threat_intelligence": {
            "total_ips_analyzed": 1,
            "ip_analysis": [
                {
                    "ip": "8.8.8.8",
                    "valid": True,
                    "is_private": False,
                    "is_loopback": False,
                    "is_reserved": False,
                    "is_multicast": False,
                    "risk_level": "Public"
                }
            ]
        },
        "ai_analysis": {}
    }

    report_file = generate_markdown_report(report_data)

    with open(report_file, "r") as file:
        content = file.read()

    assert "## Threat Intelligence Analysis" in content
    assert "Total IPs Analyzed: 1" in content
    assert "### IP: 8.8.8.8" in content
    assert "Risk Classification: Public" in content


def test_report_contains_actionable_finding(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    (tmp_path / "reports").mkdir()

    report_data = {
        "target": "example.com",
        "security_analysis": {
            "risk_score": 20,
            "risk_rating": "Medium",
            "severity_summary": {
                "Critical": 0,
                "High": 1,
                "Medium": 1,
                "Low": 0,
                "Info": 0
            },
            "findings": [
                {
                    "priority": 1,
                    "category": "HTTP Security",
                    "severity": "High",
                    "finding": "Strict-Transport-Security header is missing",
                    "risk_score": 12,
                    "exposure": 1.0,
                    "exploitability": 0.8,
                    "evidence": "HTTP response did not contain Strict-Transport-Security",
                    "recommendation": "Configure the Strict-Transport-Security security header.",
                    "remediation_details": "Add the header at the web server or application layer."
                }
            ]
        },
        "collector_status": {},
        "ai_analysis": {}
    }

    report_file = generate_markdown_report(report_data)

    with open(report_file, "r") as file:
        content = file.read()

    assert "## Executive Summary" in content
    assert "## Technical Appendix" in content
    assert "Finding Risk" in content
    assert "Evidence" in content
    assert "HTTP response did not contain Strict-Transport-Security" in content
    assert "Remediation Guidance" in content
    assert "Priority Actions" in content
