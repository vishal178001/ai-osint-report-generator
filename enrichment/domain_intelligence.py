def enrich_domain_intelligence(report_data):
    intelligence = {
        "email_security": {
            "spf_detected": False,
            "dmarc_detected": False
        },
        "mail_providers": [],
        "nameservers": [],
        "ip_addresses": []
    }

    dns_data = report_data.get("dns", {})

    txt_records = dns_data.get("TXT", [])
    mx_records = dns_data.get("MX", [])
    ns_records = dns_data.get("NS", [])
    a_records = dns_data.get("A", [])

    # Analyze TXT records
    for record in txt_records:
        record_text = str(record).lower()

        if "v=spf1" in record_text:
            intelligence["email_security"]["spf_detected"] = True

        if "v=dmarc1" in record_text:
            intelligence["email_security"]["dmarc_detected"] = True

    # Extract mail providers
    for record in mx_records:
        provider = str(record)

        if provider not in intelligence["mail_providers"]:
            intelligence["mail_providers"].append(provider)

    # Extract nameservers
    for record in ns_records:
        nameserver = str(record)

        if nameserver not in intelligence["nameservers"]:
            intelligence["nameservers"].append(nameserver)

    # Extract IP addresses
    for record in a_records:
        ip_address = str(record)

        if ip_address not in intelligence["ip_addresses"]:
            intelligence["ip_addresses"].append(ip_address)

    return intelligence
