def add_finding(findings, category, severity, finding, evidence, recommendation):
    findings.append({
        "category": category,
        "severity": severity,
        "finding": finding,
        "evidence": evidence,
        "recommendation": recommendation
    })


def analyze_security(report_data):
    findings = []

    # -------------------------
    # HTTP SECURITY ANALYSIS
    # -------------------------

    http_data = report_data.get("http", {})
    security_headers = http_data.get("security_headers", {})

    important_headers = {
        "Strict-Transport-Security": "Medium",
        "Content-Security-Policy": "Medium",
        "X-Frame-Options": "Medium",
        "X-Content-Type-Options": "Low",
        "Referrer-Policy": "Low",
        "Permissions-Policy": "Low"
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
                f"Configure the {header} security header."
            )

    # -------------------------
    # SSL CERTIFICATE ANALYSIS
    # -------------------------

    ssl_data = report_data.get("ssl", {})

    if ssl_data.get("error"):
        add_finding(
            findings,
            "SSL/TLS",
            "High",
            "SSL/TLS certificate analysis failed",
            ssl_data.get("error"),
            "Review HTTPS and certificate configuration."
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
                "Renew the SSL certificate immediately."
            )

        elif days_remaining <= 30:
            add_finding(
                findings,
                "SSL/TLS",
                "High",
                "SSL certificate expires soon",
                f"{days_remaining} days remaining",
                "Renew the certificate before expiration."
            )

    # -------------------------
    # EMAIL SECURITY ANALYSIS
    # -------------------------

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
            "Configure an SPF record to reduce email spoofing risk."
        )

    if "v=dmarc1" not in txt_text:
        add_finding(
            findings,
            "Email Security",
            "Medium",
            "DMARC record not detected",
            "No DMARC policy detected",
            "Configure DMARC and monitor authentication reports."
        )

    # -------------------------
    # RISK SCORE CALCULATION
    # -------------------------

    severity_weights = {
        "Critical": 25,
        "High": 15,
        "Medium": 8,
        "Low": 3,
        "Info": 0
    }

    risk_score = 0

    for finding in findings:
        severity = finding.get("severity", "Info")
        risk_score += severity_weights.get(severity, 0)

    risk_score = min(risk_score, 100)

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
    # -------------------------
    # ATTACK SURFACE ANALYSIS
    # -------------------------

    subdomain_data = report_data.get("subdomains", {})
    subdomain_count = subdomain_data.get("count", 0)

    if subdomain_count >= 20:
        add_finding(
            findings,
            "Attack Surface",
            "Info",
            "Large external subdomain footprint detected",
            f"{subdomain_count} unique domain names discovered",
            "Review discovered assets and remove unused or forgotten services."
        )

    # -------------------------
    # SEVERITY SUMMARY
    # -------------------------

    severity_summary = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0
    }

    for finding in findings:
        severity = finding.get("severity", "Info")

        if severity in severity_summary:
            severity_summary[severity] += 1

    # -------------------------
    # RISK SCORE CALCULATION
    # -------------------------

    severity_weights = {
        "Critical": 25,
        "High": 15,
        "Medium": 8,
        "Low": 3,
        "Info": 0
    }

    risk_score = 0

    for finding in findings:
        severity = finding.get("severity", "Info")
        risk_score += severity_weights.get(severity, 0)

    risk_score = min(risk_score, 100)

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
        "findings": findings
    }
