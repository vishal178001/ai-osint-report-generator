# AI-Assisted OSINT Report Generator

A Python-based OSINT automation and security analysis tool that collects publicly available domain information, analyzes security findings, calculates risk scores, and generates structured Markdown and JSON reports.

## Features

- DNS record collection
- WHOIS information gathering
- theHarvester integration
- HTTP security header analysis
- SSL/TLS certificate analysis
- Subdomain discovery
- Technology detection
- Email security analysis for SPF and DMARC
- Security finding classification
- Severity summary
- Risk score and risk rating
- Local AI-assisted analysis
- Markdown report generation
- JSON output
- Collector failure handling
- Collector timeout protection
- Logging
- Automated tests

## Project Structure

- collectors/ - OSINT data collection modules
- ai/ - Security and AI analysis modules
- reports/ - Report generation code
- utils/ - Validation, logging, and safe execution utilities
- config/ - Project configuration
- tests/ - Automated test suite
- data/ - Generated JSON results
- logs/ - Application logs
- main.py - Main CLI entry point

## Installation

Clone the repository and enter the project directory.

Create a virtual environment:

    python3 -m venv .venv

Activate it:

    source .venv/bin/activate

Install dependencies:

    python -m pip install -r requirements.txt

## Usage

Run a scan:

    python main.py -t example.com

Use only domains you own or are authorized to assess.

## Testing

Run the complete test suite:

    python -m pytest -v

## Output

The application generates:

- Structured JSON OSINT data in data/
- Markdown security reports in reports/
- Execution logs in logs/

## Disclaimer

This project is intended for educational purposes, defensive security research, and authorized OSINT assessments. Users are responsible for complying with applicable laws and obtaining authorization where required.
