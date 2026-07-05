from collectors.dns_collector import collect_dns
import argparse
import json
from enrichment.domain_intelligence import enrich_domain_intelligence
from collectors.whois_collector import collect_whois
from collectors.theharvester_collector import collect_theharvester
from collectors.http_collector import collect_http
from collectors.ssl_collector import collect_ssl
from collectors.subdomain_collector import collect_subdomains
from collectors.tech_collector import collect_technologies
from ai.security_analyzer import analyze_security
from reports.report_generator import generate_markdown_report
from ai.llm_analyzer import generate_ai_analysis
from utils.validator import validate_domain
from utils.logger import logger
from utils.safe_runner import safe_collect
from config.settings import DATA_DIR
from datetime import datetime


def main():
    print("=" * 50)
    print("AI-Assisted OSINT Report Generator")
    print("=" * 50)

    scan_start = datetime.now()

    parser = argparse.ArgumentParser(description="AI OSINT Report Generator")
    parser.add_argument("-t", "--target", help="Target domain", required=True)
    args = parser.parse_args()

    target = args.target.strip()
    logger.info(f"Scan requested for target: {target}")

    if not validate_domain(target):
        logger.warning(f"Invalid domain input: {target}")
        print("\n[-] Invalid domain format.")
        print("[-] Example of valid input: example.com")
        return

    print(f"\n[+] Target: {target}")
    print("[+] Collecting DNS information...\n")

    results, dns_status = safe_collect("DNS", collect_dns, target)

    print("[+] Collecting WHOIS information...\n")
    whois_results, whois_status = safe_collect("WHOIS", collect_whois, target)
    print("[+] Running theHarvester...\n")
    harvester_results, harvester_status = safe_collect("theHarvester", collect_theharvester, target)
    print("[+] Collecting HTTP information...\n")
    http_results, http_status = safe_collect("HTTP", collect_http, target)
    print("[+] Collecting SSL/TLS certificate information...\n")
    ssl_results, ssl_status = safe_collect("SSL/TLS", collect_ssl, target)
    print("[+] Discovering subdomains...\n")
    subdomain_results, subdomain_status = safe_collect("Subdomain Discovery", collect_subdomains, target)
    print("[+] Detecting technologies...\n")
    tech_results, tech_status = safe_collect("Technology Detection", collect_technologies, target)

    scan_end = datetime.now()
    scan_duration = (scan_end - scan_start).total_seconds()

    report_data = {
        "target": target,
        "scan_start": scan_start.isoformat(),
        "scan_end": scan_end.isoformat(),
        "scan_duration_seconds": round(scan_duration, 2),

        "collector_status": {
        "dns": dns_status ,
        "whois": whois_status ,
        "theharvester": harvester_status ,
        "http": http_status ,
        "ssl": ssl_status ,
        "subdomains": subdomain_status ,
        "technologies": tech_status
        },

        "dns": results ,
        "whois": whois_results ,
        "theharvester": harvester_results ,
        "http": http_results ,
        "ssl": ssl_results ,
        "subdomains": subdomain_results ,
        "technologies": tech_results ,
    }

    print("[+] Enriching domain intelligence...\n")

    domain_intelligence = enrich_domain_intelligence(report_data)
    report_data["domain_intelligence"] = domain_intelligence


    print("[+] Analyzing security findings...\n")
    analysis_results = analyze_security(report_data)

    report_data["security_analysis"] = analysis_results

    print("[+] Generating local AI analysis...\n")
    ai_results = generate_ai_analysis(report_data)

    report_data["ai_analysis"] = ai_results

    print("[+] Generating Markdown report...\n")
    report_file = generate_markdown_report(report_data)

    print(f"[+] Markdown report saved to: {report_file}")

    for record_type, records in results.items():
        print(f"{record_type} Records:")

        for record in records:
            print(f"  {record}")

        print()

    output_file = f"{DATA_DIR}/{target}_osint.json"

    with open(output_file, "w") as file:
        json.dump(report_data, file, indent=4)

    print(f"[+] Results saved to: {output_file}")
    logger.info(
    f"Scan completed for {target} in {scan_duration:.2f} seconds")

    print("\n" + "=" * 50)
    print("[+] Scan completed successfully")
    print(f"[+] Target: {target}")
    print(f"[+] Duration: {scan_duration:.2f} seconds")
    print(f"[+] Report: {report_file}")
    print(f"[+] JSON Data: {output_file}")
    print("=" * 50)

if __name__ == "__main__":
    main()
