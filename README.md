# AI-Assisted OSINT Report Generator

> Automate public-domain reconnaissance, security analysis, risk scoring, and structured OSINT reporting from one Python workflow.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Tests](https://github.com/vishal178001/ai-osint-report-generator/actions/workflows/tests.yml/badge.svg)](https://github.com/vishal178001/ai-osint-report-generator/actions/workflows/tests.yml)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## Overview

AI-Assisted OSINT Report Generator is an open-source Python project that turns publicly available domain intelligence into structured security findings and readable reports.

The project is designed around a practical problem: OSINT tools often produce useful information in separate outputs, while analysts still have to collect, normalize, interpret, prioritize, and document those findings manually.

This project brings those steps together into a single workflow:

```text
Target Domain
     |
     v
+---------------------+
|  OSINT Collectors   |
+----------+----------+
           |
   +-------+-------+----------------+
   |       |       |                |
  DNS    WHOIS   HTTP/TLS    Subdomains/Tech
   |       |       |                |
   +-------+-------+----------------+
           |
           v
+--------------------------+
| Domain / Threat Enrichment|
+------------+-------------+
             |
             v
+--------------------------+
| Security Analysis        |
| Findings + Risk Scoring  |
+------------+-------------+
             |
             v
+--------------------------+
| AI-Assisted Interpretation|
+------------+-------------+
             |
             v
+--------------------------+
| Structured Reports       |
| Markdown + JSON         |
+--------------------------+
```

## What it can do

### Reconnaissance and collection

- DNS record collection
- WHOIS information gathering
- theHarvester integration
- HTTP information and security-header analysis
- SSL/TLS certificate analysis
- Subdomain discovery
- Technology detection
- SPF and DMARC analysis

### Analysis and enrichment

- Security finding classification
- Severity summaries
- Risk scoring and risk rating
- Domain intelligence enrichment
- Threat-intelligence provider integration
- Collector status tracking
- Timeout and failure handling

### AI-assisted reporting

- Local AI-assisted analysis
- Structured security summaries
- Markdown report generation
- JSON output for further automation

### Web dashboard

The repository includes a Flask-based local dashboard. Flask is installed automatically from `requirements.txt`, so a fresh clone does not require a separate dashboard dependency setup.

The dashboard provides:

- Target/domain input
- One-click scan execution
- Scan output
- View Markdown report
- View JSON report

Start it with:

```bash
python dashboard.py
```

Then open:

```text
http://127.0.0.1:5000
```

The original CLI remains available:

```bash
python main.py -t example.com
```

## Why this project?

A typical OSINT workflow can involve several independent tools and a large amount of manual report preparation. This project explores how automation and AI can reduce that repetitive work while keeping the underlying evidence and security findings structured.

The goal is not to replace an analyst. The goal is to give an analyst a repeatable starting point for reconnaissance, triage, interpretation, and reporting.

## Project structure

```text
ai-osint-report-generator/
├── ai/                     # Security analysis and AI-assisted analysis
├── app/                    # Application package
├── collectors/             # OSINT collection modules
├── config/                 # Configuration and runtime directories
├── enrichment/             # Domain and threat intelligence enrichment
│   └── providers/          # Intelligence provider implementations
├── reports/                # Markdown report generation
├── templates/              # Flask dashboard HTML templates
├── static/                 # Dashboard CSS
├── tests/                  # Automated tests
├── utils/                  # Validation, logging, safe execution
├── data/                   # Generated scan data (ignored)
├── logs/                   # Runtime logs (ignored)
├── dashboard.py            # Web dashboard entry point
├── main.py                 # CLI entry point
├── requirements.txt        # Python dependencies
└── .env.example            # Environment configuration example
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/vishal178001/ai-osint-report-generator.git
cd ai-osint-report-generator
```

### 2. Create a virtual environment

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows PowerShell:

```powershell
python -m venv .venv
.venv\\Scripts\\Activate.ps1
```

### 3. Install all dependencies

The dashboard dependency is included in the main requirements file. No separate Flask installation is required.

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

The project creates its runtime `data/`, `reports/`, and `logs/` directories automatically after installation/import, so a fresh clone does not require manual directory creation.

### 4. Configure optional integrations

Copy the example environment file and add only the credentials you are authorized to use:

```bash
cp .env.example .env
```

On Windows:

```powershell
Copy-Item .env.example .env
```

## Usage

### CLI

Run a scan against a domain you own or are authorized to assess:

```bash
python main.py -t example.com
```

### Web dashboard

Start the local dashboard:

```bash
python dashboard.py
```

Open:

```text
http://127.0.0.1:5000
```

Enter an authorized target and select **Start Scan**. After the scan, the dashboard provides links to the generated Markdown and JSON reports.

### Generated output

- JSON scan data: `data/`
- Markdown security reports: `reports/`
- Runtime logs: `logs/`

Generated scan data and logs are intentionally excluded from version control.

## Testing

Run the complete test suite locally:

```bash
python -m pytest -v
```

The repository also includes a GitHub Actions workflow that runs the test suite automatically on pushes and pull requests.

## Responsible use

This project is intended for:

- Educational cybersecurity work
- Defensive security research
- Authorized OSINT assessments
- Security analysis of domains you own or have permission to assess

Do not use the project to access, collect, or analyze information in violation of applicable laws, contracts, terms of service, or authorization boundaries.

The output is an automated analysis aid and should be reviewed by a qualified human before being used for security decisions.

## Current status

The project is an actively developed early-stage open-source tool. The current focus is reliability, modular collectors, structured security analysis, AI-assisted reporting, testing, documentation, and a local web dashboard.

Current development priorities include:

- Expanding OSINT and threat-intelligence integrations
- Improving local LLM support
- Improving report quality and usability
- Expanding automated test coverage
- Improving contributor documentation
- Making the collection and analysis pipeline easier to extend
- Expanding dashboard capabilities

## Contributing

Contributions, bug reports, documentation improvements, and ideas are welcome.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow.

## Security

If you discover a security issue, please see [SECURITY.md](SECURITY.md) instead of publicly posting sensitive details in an issue.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
