"""
Deterministic risk scoring for OSINT findings.

This is a lightweight prioritization model, not a vulnerability severity
standard such as CVSS. Scores should be reviewed in organizational context.
"""

SEVERITY_POINTS = {
    "Critical": 25,
    "High": 15,
    "Medium": 8,
    "Low": 3,
    "Info": 0,
}

# Factors are intentionally conservative. Exposure reflects public reach;
# exploitability reflects how directly the observed condition can contribute
# to abuse. These defaults can be refined when stronger evidence is available.
CATEGORY_EXPLOITABILITY = {
    "HTTP Security": 0.70,
    "SSL/TLS": 0.80,
    "Email Security": 0.70,
    "Threat Intelligence": 0.90,
    "Attack Surface": 0.40,
}


def calculate_finding_risk(severity, exposure=1.0, exploitability=1.0):
    base = SEVERITY_POINTS.get(severity, 0)
    score = base * max(0.0, min(exposure, 1.0)) * max(
        0.0, min(exploitability, 1.0)
    )
    return round(score, 2)


def enrich_finding_risk(finding):
    severity = finding.get("severity", "Info")
    category = finding.get("category", "Unknown")

    exposure = finding.get("exposure", 1.0)
    exploitability = finding.get(
        "exploitability",
        CATEGORY_EXPLOITABILITY.get(category, 0.70),
    )

    finding["exposure"] = round(exposure, 2)
    finding["exploitability"] = round(exploitability, 2)
    finding["risk_score"] = calculate_finding_risk(
        severity,
        exposure,
        exploitability,
    )

    return finding


def calculate_domain_risk(findings):
    total = sum(
        finding.get("risk_score", 0)
        for finding in findings
    )
    return min(round(total, 2), 100.0)
