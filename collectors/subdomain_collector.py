import requests


def collect_subdomains(domain):
    result = {
        "source": "crt.sh",
        "subdomains": [],
        "count": 0,
        "error": ""
    }

    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"

        response = requests.get(
            url,
            timeout=30,
            headers={
                "User-Agent": "Mozilla/5.0 OSINT-Research-Tool"
            }
        )

        response.raise_for_status()

        data = response.json()
        subdomains = set()

        for certificate in data:
            names = certificate.get("name_value", "").split("\n")

            for name in names:
                name = name.strip().lower()

                if name.startswith("*."):
                    name = name[2:]

                if name == domain or name.endswith("." + domain):
                    subdomains.add(name)

        result["subdomains"] = sorted(subdomains)
        result["count"] = len(subdomains)

    except Exception as error:
        result["error"] = str(error)

    return result
