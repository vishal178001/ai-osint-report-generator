def generate_ai_analysis(report_data):
    security_analysis = report_data.get("security_analysis", {})

    findings = security_analysis.get("findings", [])
    risk_score = security_analysis.get("risk_score", 0)
    risk_rating = security_analysis.get("risk_rating", "Unknown")
    severity_summary = security_analysis.get("severity_summary", {})
    domain_intelligence = report_data.get("domain_intelligence", {})

    email_security = domain_intelligence.get("email_security", {})
    mail_providers = domain_intelligence.get("mail_providers", [])
    nameservers = domain_intelligence.get("nameservers", [])
    ip_addresses = domain_intelligence.get("ip_addresses", [])

    if not findings:
        return {
            "summary": "No significant security findings were identified.",
            "priority_actions": [],
            "risk_context": "The available OSINT data did not reveal major security concerns."
        }

    priority_actions = []

    if not email_security.get("spf_detected", False):
        priority_actions.append(
            "Configure an SPF record to reduce the risk of email spoofing."
        )

    if not email_security.get("dmarc_detected", False):
        priority_actions.append(
            "Configure a DMARC policy to improve protection against email spoofing and phishing."
        )

    for finding in findings:
        severity = finding.get("severity", "Info")
        recommendation = finding.get("recommendation", "")

        if severity in ["Critical", "High"] and recommendation:
            priority_actions.append(recommendation)

    # Remove duplicate recommendations
    priority_actions = list(dict.fromkeys(priority_actions))

    critical = severity_summary.get("Critical", 0)
    high = severity_summary.get("High", 0)
    medium = severity_summary.get("Medium", 0)

    summary = (
        f"The target received a {risk_rating} risk rating with a "
        f"risk score of {risk_score}/100. "
        f"The analysis identified {len(findings)} findings, including "
        f"{critical} critical, {high} high, and {medium} medium severity findings."
    )

    if critical > 0:
        risk_context = (
            "Critical security issues were identified and should be "
            "addressed immediately."
        )
    elif high > 0:
        risk_context = (
            "High-severity weaknesses were identified and should be "
            "prioritized for remediation."
        )
    elif medium > 0:
        risk_context = (
            "The target has moderate security weaknesses that should "
            "be reviewed and remediated."
        )
    else:
        risk_context = (
            "The identified issues are primarily low severity or informational."
        )

    intelligence_context = {
        "spf_enabled": email_security.get("spf_detected", False),
        "dmarc_enabled": email_security.get("dmarc_detected", False),
        "mail_providers": mail_providers,
        "nameservers": nameservers,
        "ip_addresses": ip_addresses,
    }

    return {
        "summary": summary,
        "priority_actions": priority_actions,
        "risk_context": risk_context,
        "domain_intelligence_context": intelligence_context,
    }
