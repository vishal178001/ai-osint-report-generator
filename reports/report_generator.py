from datetime import datetime
from config.settings import REPORT_DIR, REPORT_EXTENSION

def generate_markdown_report(report_data):
    target = report_data.get("target", "Unknown")
    analysis = report_data.get("security_analysis", {})
    findings = analysis.get("findings", [])
    ai_analysis = report_data.get("ai_analysis", {})
    risk_score = analysis.get("risk_score", 0)
    risk_rating = analysis.get("risk_rating", "Unknown")
    severity_summary = analysis.get("severity_summary", {})
    collector_status = report_data.get("collector_status", {})
    scan_start = report_data.get("scan_start", "Unknown")
    scan_end = report_data.get("scan_end", "Unknown")
    scan_duration = report_data.get("scan_duration_seconds", "Unknown")

    report = []

    report.append(f"# AI-Assisted OSINT Security Report")
    report.append("")
    report.append(f"Target: {target}")
    report.append(f"Generated: {datetime.now().isoformat()}")
    report.append(f"Scan Start: {scan_start}")
    report.append(f"Scan End: {scan_end}")
    report.append(f"Scan Duration: {scan_duration} seconds")
    report.append("")
    report.append("## Collection Status")
    report.append("")

    if collector_status:
        for collector, status in collector_status.items():
            report.append(f"- {collector}: {status}")
    else:
        report.append("No collector status information available.")

    report.append("")

    report.append("## Executive Summary")
    report.append("")
    report.append(
        f"The OSINT analysis identified {len(findings)} security findings."
    )
    report.append("")
    report.append("## Risk Overview")
    report.append("")
    report.append(f"Overall Risk Rating: {risk_rating}")
    report.append(f"Risk Score: {risk_score}/100")
    report.append("")

    report.append("### Severity Summary")
    report.append("")

    for severity in ["Critical", "High", "Medium", "Low", "Info"]:
        count = severity_summary.get(severity, 0)
    report.append(f"- {severity}: {count}")

    report.append("")

    report.append("## AI Analysis Summary")
    report.append("")

    summary = ai_analysis.get(
        "summary",
        "No AI analysis summary available."
    )
    report.append(summary)
    report.append("")

    report.append("### Risk Context")
    report.append("")

    risk_context = ai_analysis.get(
        "risk_context",
        "No risk context available."
    )
    report.append(risk_context)
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

    report.append("## Security Findings")
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
                f"Category: {finding.get('category', 'Unknown')}"
            )
            report.append(
                f"Severity: {finding.get('severity', 'Unknown')}"
            )
            report.append("")
            report.append(
                f"Recommendation: "
                f"{finding.get('recommendation', 'No recommendation available')}"
            )
            report.append("")

    ai_data = report_data.get("ai_analysis", {})

    if ai_data and not ai_data.get("error"):
        report.append("")
        report.append("## AI-Assisted Executive Summary")
        report.append("")
        report.append(
            ai_data.get(
                "executive_summary",
                "AI analysis was completed, but no summary was returned."
            )
        )
        report.append("")

    output_file = f"{REPORT_DIR}/{target}_report{REPORT_EXTENSION}"

    with open(output_file, "w") as file:
        file.write("\n".join(report))

    return output_file
