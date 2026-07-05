import ipaddress
from enrichment.providers.abuseipdb_provider import AbuseIPDBProvider

def analyze_ip(ip_address):
    """
    Analyze basic threat-intelligence characteristics of an IP address.
    """

    result = {
        "ip": ip_address,
        "valid": False,
        "is_private": False,
        "is_loopback": False,
        "is_reserved": False,
        "is_multicast": False,
        "risk_level": "Unknown",
    }

    try:
        ip = ipaddress.ip_address(ip_address)

        result["valid"] = True
        result["is_private"] = ip.is_private
        result["is_loopback"] = ip.is_loopback
        result["is_reserved"] = ip.is_reserved
        result["is_multicast"] = ip.is_multicast

        if ip.is_loopback or ip.is_multicast:
            result["risk_level"] = "Suspicious"
        elif ip.is_private:
            result["risk_level"] = "Internal"
        elif ip.is_reserved:
            result["risk_level"] = "Reserved"
        else:
            result["risk_level"] = "Public"

    except ValueError:
        result["risk_level"] = "Invalid"

    return result


def enrich_threat_intelligence(report_data):
    """
    Analyze all IP addresses collected during OSINT scanning.
    """

    domain_intelligence = report_data.get("domain_intelligence", {})
    ip_addresses = domain_intelligence.get("ip_addresses", [])

    analyzed_ips = []

    for ip_address in ip_addresses:
        analyzed_ips.append(analyze_ip(ip_address))

    provider = AbuseIPDBProvider()

    provider_results = []

    for ip_address in ip_addresses:
        provider_results.append(provider.check_ip(ip_address))


    return {
        "total_ips_analyzed": len(analyzed_ips),
        "ip_analysis": analyzed_ips,
        "provider_results": provider_results, 
   }
