from datetime import datetime
from config.settings import REPORT_DIR, REPORT_EXTENSION
import os


def generate_markdown_report(report_data):
    target = report_data.get("target", "Unknown")
    analysis = report_data.get("security_analysis", {})
    findings = analysis.get("findings", [])
    threat_intelligence = report_data.get("threat_intelligence", {})
    ai_analysis = report_data.get("ai_analysis", {})
    risk_score = analysis.get("risk_score", 0)
    risk_rating = analysis.get("risk_rating", "Unknown")
    severity_summary = analysis.get("severity_summary", {})
    collector_status = report_data.get("collector_status", {})
    scan_start = report_data.get("scan_start", "Unknown")
    scan_end = report_data.get("scan_end", "Unknown")
    scan_duration = report_data.get("scan_duration_seconds", "Unknown")
    risk_methodology = analysis.get("risk_methodology", {})

    report = []

    report.append("# AI-Assisted OSINT Security Report")
    report.append("")
    report.append(f"Target: {target}")
    report.append(f"Generated: {datetime.now().isoformat()}")
    report.append(f"Scan Start: {scan_start}")
    report.append(f"Scan End: {scan_end}")
    report.append(f"Scan Duration: {scan_duration} seconds")
    report.append("")

    # ==========================================================
    # EXECUTIVE SUMMARY
    # ==========================================================
    report.append("## Executive Summary")
    report.append("")
    report.append(
        f"The assessment identified {len(findings)} security findings "
        f"with an overall risk score of {risk_score}/100 "
        f"and a risk rating of {risk_rating}."
    )
    report.append("")
    report.append("### Risk at a Glance")
    report.append("")
    report.append(f"- **Overall Risk:** {risk_rating}")
    report.append(f"- **Risk Score:** {risk_score}/100")
    report.append(f"- **Total Findings:** {len(findings)}")

    for severity in ["Critical", "High", "Medium", "Low", "Info"]:
        report.append(
            f"- **{severity} Findings:** "
            f"{severity_summary.get(severity, 0)}"
        )

    report.append("")

    report.append("### Priority Actions")
    report.append("")

    prioritized = [
        finding for finding in findings
        if finding.get("severity") != "Info"
    ][:5]

    if prioritized:
        for finding in prioritized:
            report.append(
                f"{finding.get('priority', '-')}."
                f" **{finding.get('finding', 'Unknown Finding')}** "
                f"— {finding.get('recommendation', 'Review finding')} "
                f"(risk {finding.get('risk_score', 0)}/25)."
            )
    else:
        report.append("No non-informational priority actions identified.")

    report.append("")

    ai_summary = ai_analysis.get("executive_summary")
    if ai_summary:
        report.append("### AI-Assisted Executive Context")
        report.append("")
        report.append(ai_summary)
        report.append("")

    report.append(
        "> Automated risk scoring is a prioritization aid, not a substitute "
        "for business context or a formal vulnerability standard. Findings "
        "should be validated by a qualified reviewer."
    )
    report.append("")

    # ==========================================================
    # COLLECTION STATUS
    # ==========================================================
    report.append("## Collection Status")
    report.append("")

    if collector_status:
        for collector, status in collector_status.items():
            report.append(f"- {collector}: {status}")
    else:
        report.append("No collector status information available.")

    report.append("")

    # ==========================================================
    # RISK METHODOLOGY
    # ==========================================================
    report.append("## Risk Methodology")
    report.append("")
    report.append(
        risk_methodology.get(
            "description",
            "Finding risk uses severity, exposure, and exploitability.",
        )
    )
    report.append("")
    report.append(
        "This lightweight model is designed for transparent prioritization "
        "of OSINT findings. It should be calibrated to organizational "
        "context before being used for formal risk decisions."
    )
    report.append("")

    # ==========================================================
    # DOMAIN INTELLIGENCE
    # ==========================================================
    domain_intelligence = report_data.get("domain_intelligence", {})

    report.append("## Domain Intelligence")
    report.append("")

    email_security = domain_intelligence.get("email_security", {})

    report.append("### Email Security")
    report.append(
        f"- SPF Detected: {email_security.get('spf_detected', False)}"
    )
    report.append(
        f"- DMARC Detected: {email_security.get('dmarc_detected', False)}"
    )
    report.append("")

    report.append("### Mail Providers")
    for provider in domain_intelligence.get("mail_providers", []):
        report.append(f"- {provider}")
    report.append("")

    report.append("### Nameservers")
    for nameserver in domain_intelligence.get("nameservers", []):
        report.append(f"- {nameserver}")
    report.append("")

    report.append("### IP Addresses")
    for ip in domain_intelligence.get("ip_addresses", []):
        report.append(f"- {ip}")
    report.append("")

    # ==========================================================
    # THREAT INTELLIGENCE
    # ==========================================================
    report.append("## Threat Intelligence Analysis")
    report.append("")

    total_ips = threat_intelligence.get("total_ips_analyzed", 0)
    report.append(f"Total IPs Analyzed: {total_ips}")
    report.append("")

    ip_analysis = threat_intelligence.get("ip_analysis", [])

    if ip_analysis:
        for ip_data in ip_analysis:
            report.append(f"### IP: {ip_data.get('ip', 'Unknown')}")
            report.append("")
            report.append(f"- Valid: {ip_data.get('valid', False)}")
            report.append(
                f"- Risk Classification: "
                f"{ip_data.get('risk_level', 'Unknown')}"
            )
            report.append(
                f"- Private: {ip_data.get('is_private', False)}"
            )
            report.append(
                f"- Reserved: {ip_data.get('is_reserved', False)}"
            )
            report.append("")
    else:
        report.append("No IP addresses were available for analysis.")
        report.append("")

    # ==========================================================
    # TECHNICAL APPENDIX
    # ==========================================================
    report.append("## Technical Appendix")
    report.append("")
    report.append(
        "This section preserves the evidence, prioritization factors, "
        "and remediation context behind each automated finding."
    )
    report.append("")

    if not findings:
        report.append("No security findings were identified.")
    else:
        for number, finding in enumerate(findings, start=1):
            report.append(
                f"### {number}. {finding.get('finding', 'Unknown Finding')}"
            )
            report.append("")
            report.append(
                f"- **Priority:** {finding.get('priority', number)}"
            )
            report.append(
                f"- **Category:** {finding.get('category', 'Unknown')}"
            )
            report.append(
                f"- **Severity:** {finding.get('severity', 'Unknown')}"
            )
            report.append(
                f"- **Finding Risk:** "
                f"{finding.get('risk_score', 0)}/25"
            )
            report.append(
                f"- **Exposure:** {finding.get('exposure', 0)}"
            )
            report.append(
                f"- **Exploitability:** "
                f"{finding.get('exploitability', 0)}"
            )
            report.append("")
            report.append("**Evidence**")
            report.append("")
            report.append(
                f"{finding.get('evidence', 'No evidence recorded.')}"
            )
            report.append("")
            report.append("**Recommendation**")
            report.append("")
            report.append(
                finding.get(
                    "recommendation",
                    "No recommendation available.",
                )
            )
            report.append("")

            remediation = finding.get("remediation_details")
            if remediation:
                report.append("**Remediation Guidance**")
                report.append("")
                report.append(remediation)
                report.append("")

    # ==========================================================
    # AI ANALYSIS
    # ==========================================================
    report.append("## AI Analysis")
    report.append("")

    summary = ai_analysis.get(
        "summary",
        "No AI analysis summary available.",
    )
    report.append(summary)
    report.append("")

    report.append("### Risk Context")
    report.append("")
    report.append(
        ai_analysis.get(
            "risk_context",
            "No risk context available.",
        )
    )
    report.append("")

    report.append("### Priority Actions")
    report.append("")

    priority_actions = ai_analysis.get("priority_actions", [])

    if priority_actions:
        for action in priority_actions:
            report.append(f"- {action}")
    else:
        report.append("No urgent priority actions identified.")

    report.append("")

    os.makedirs(REPORT_DIR, exist_ok=True)
    output_file = f"{REPORT_DIR}/{target}_report{REPORT_EXTENSION}"

    with open(output_file, "w", encoding="utf-8") as file:
        file.write("\n".join(report))

    return output_file
