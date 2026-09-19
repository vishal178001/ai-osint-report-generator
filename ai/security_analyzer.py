from ai.risk_model import calculate_domain_risk, enrich_finding_risk


def add_finding(
    findings,
    category,
    severity,
    finding,
    evidence,
    recommendation,
    remediation_details=None,
    exposure=1.0,
    exploitability=None,
):
    item = {
        "category": category,
        "severity": severity,
        "finding": finding,
        "evidence": evidence,
        "recommendation": recommendation,
    }

    if remediation_details:
        item["remediation_details"] = remediation_details

    item["exposure"] = exposure

    if exploitability is not None:
        item["exploitability"] = exploitability

    findings.append(enrich_finding_risk(item))


def analyze_security(report_data):
    findings = []

    threat_intelligence = report_data.get("threat_intelligence", {})
    provider_results = threat_intelligence.get("provider_results", [])

    # HTTP SECURITY ANALYSIS
    http_data = report_data.get("http", {})
    security_headers = http_data.get("security_headers", {})

    important_headers = {
        "Strict-Transport-Security": "Medium",
        "Content-Security-Policy": "Medium",
        "X-Frame-Options": "Medium",
        "X-Content-Type-Options": "Low",
        "Referrer-Policy": "Low",
        "Permissions-Policy": "Low",
    }

    for header, severity in important_headers.items():
        status = security_headers.get(header, "Missing")

        if status == "Missing":
            add_finding(
                findings,
                "HTTP Security",
                severity,
                f"{header} header is missing",
                f"HTTP response did not contain {header}",
                f"Configure the {header} security header.",
                (
                    f"Add {header} at the web server or application layer "
                    "and verify the response on every relevant HTTPS route."
                ),
            )

    # SSL/TLS ANALYSIS
    ssl_data = report_data.get("ssl", {})

    if ssl_data.get("error"):
        add_finding(
            findings,
            "SSL/TLS",
            "High",
            "SSL/TLS certificate analysis failed",
            ssl_data.get("error"),
            "Review HTTPS and certificate configuration.",
            (
                "Validate certificate retrieval, chain configuration, "
                "hostname coverage, and TLS service availability."
            ),
        )

    days_remaining = ssl_data.get("days_remaining")

    if isinstance(days_remaining, int):
        if days_remaining < 0:
            add_finding(
                findings,
                "SSL/TLS",
                "Critical",
                "SSL certificate has expired",
                f"Certificate expired {abs(days_remaining)} days ago",
                "Renew the SSL certificate immediately.",
                (
                    "Replace the expired certificate, deploy the renewed "
                    "certificate chain, and verify the public endpoint."
                ),
            )
        elif days_remaining <= 30:
            add_finding(
                findings,
                "SSL/TLS",
                "High",
                "SSL certificate expires soon",
                f"{days_remaining} days remaining",
                "Renew the certificate before expiration.",
                (
                    "Schedule certificate renewal before the remaining "
                    "validity window closes and verify automated renewal."
                ),
            )

    # EMAIL SECURITY ANALYSIS
    dns_data = report_data.get("dns", {})
    txt_records = dns_data.get("TXT", [])
    txt_text = " ".join(str(record).lower() for record in txt_records)

    if "v=spf1" not in txt_text:
        add_finding(
            findings,
            "Email Security",
            "Medium",
            "SPF record not detected",
            "No SPF policy found in TXT records",
            "Configure an SPF record to reduce email spoofing risk.",
            (
                "Publish one SPF TXT record at the domain root that lists "
                "the legitimate sending services. Keep the policy within "
                "the SPF DNS-lookup limit and validate it after publishing."
            ),
        )

    if "v=dmarc1" not in txt_text:
        add_finding(
            findings,
            "Email Security",
            "Medium",
            "DMARC record not detected",
            "No DMARC policy detected",
            "Configure DMARC and monitor authentication reports.",
            (
                "Publish a TXT record at _dmarc.<target>. A common starting "
                "pattern is "
                "'v=DMARC1; p=none; rua=mailto:<reporting-mailbox>'. "
                "Use an organization-controlled reporting mailbox and "
                "tighten the policy only after legitimate senders are "
                "validated."
            ),
        )

    # THREAT INTELLIGENCE ANALYSIS
    for provider_result in provider_results:
        if provider_result.get("status") != "success":
            continue

        abuse_score = provider_result.get("abuse_confidence_score", 0)
        ip_address = provider_result.get("ip", "Unknown")

        if abuse_score >= 75:
            add_finding(
                findings,
                "Threat Intelligence",
                "High",
                "High-Risk Malicious IP Detected",
                f"IP {ip_address} has an abuse confidence score of {abuse_score}%.",
                f"Investigate and consider blocking IP address {ip_address}.",
                (
                    f"Validate the reputation finding against additional "
                    f"evidence before blocking {ip_address}; review recent "
                    "traffic and ownership context."
                ),
            )
        elif abuse_score >= 25:
            add_finding(
                findings,
                "Threat Intelligence",
                "Medium",
                "Suspicious IP Reputation",
                f"IP {ip_address} has an abuse confidence score of {abuse_score}%.",
                f"Review activity associated with IP address {ip_address}.",
                (
                    f"Correlate the reputation result for {ip_address} with "
                    "DNS, asset ownership, and observed activity before "
                    "taking containment action."
                ),
            )

    # ATTACK SURFACE ANALYSIS
    subdomain_data = report_data.get("subdomains", {})
    subdomain_count = subdomain_data.get("count", 0)

    if subdomain_count >= 20:
        add_finding(
            findings,
            "Attack Surface",
            "Info",
            "Large external subdomain footprint detected",
            f"{subdomain_count} unique domain names discovered",
            "Review discovered assets and remove unused or forgotten services.",
            (
                "Validate ownership and business purpose for discovered "
                "subdomains, then retire or protect assets that are no "
                "longer required."
            ),
            exploitability=0.40,
        )

    # Severity summary
    severity_summary = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0,
    }

    for finding in findings:
        severity = finding.get("severity", "Info")
        if severity in severity_summary:
            severity_summary[severity] += 1

    # Highest-risk findings first for actionable reporting.
    findings.sort(
        key=lambda item: item.get("risk_score", 0),
        reverse=True,
    )

    for index, finding in enumerate(findings, start=1):
        finding["priority"] = index

    risk_score = calculate_domain_risk(findings)

    if risk_score >= 75:
        risk_rating = "Critical"
    elif risk_score >= 50:
        risk_rating = "High"
    elif risk_score >= 25:
        risk_rating = "Medium"
    elif risk_score > 0:
        risk_rating = "Low"
    else:
        risk_rating = "Informational"

    return {
        "total_findings": len(findings),
        "risk_score": risk_score,
        "risk_rating": risk_rating,
        "severity_summary": severity_summary,
        "findings": findings,
        "risk_methodology": {
            "description": (
                "Finding risk = severity points × exposure × exploitability; "
                "domain risk is the capped sum of finding risk scores."
            ),
            "severity_points": {
                "Critical": 25,
                "High": 15,
                "Medium": 8,
                "Low": 3,
                "Info": 0,
            },
            "exposure_scale": "0.0–1.0",
            "exploitability_scale": "0.0–1.0",
            "domain_score_cap": 100,
        },
    }
