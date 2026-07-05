import dns.resolver


def collect_dns(domain):
    results = {
        "A": [],
        "MX": [],
        "NS": [],
        "TXT": []
    }

    for record_type in results:
        try:
            answers = dns.resolver.resolve(domain, record_type)

            for answer in answers:
                results[record_type].append(str(answer))

        except Exception as error:
            results[record_type].append(f"Error: {error}")

    return results
