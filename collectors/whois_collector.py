import whois


def make_serializable(value):
    if isinstance(value, list):
        return [str(item) for item in value]

    if value is None:
        return None

    return str(value)


def collect_whois(domain):
    try:
        data = whois.whois(domain)

        results = {
            "domain_name": make_serializable(data.domain_name),
            "registrar": make_serializable(data.registrar),
            "creation_date": make_serializable(data.creation_date),
            "expiration_date": make_serializable(data.expiration_date),
            "updated_date": make_serializable(data.updated_date),
            "name_servers": make_serializable(data.name_servers),
            "status": make_serializable(data.status)
        }

        return results

    except Exception as error:
        return {
            "error": str(error)
        }
