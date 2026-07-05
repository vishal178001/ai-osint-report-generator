import requests
from bs4 import BeautifulSoup


def collect_http(domain):
    result = {
        "url": "",
        "status_code": None,
        "title": "",
        "server": "",
        "content_type": "",
        "security_headers": {},
        "error": ""
    }

    try:
        url = f"https://{domain}"

        response = requests.get(
            url,
            timeout=15,
            allow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0 OSINT-Research-Tool"
            }
        )

        result["url"] = response.url
        result["status_code"] = response.status_code
        result["server"] = response.headers.get("Server", "")
        result["content_type"] = response.headers.get(
            "Content-Type", ""
        )

        soup = BeautifulSoup(response.text, "html.parser")

        if soup.title:
            result["title"] = soup.title.string.strip()

        headers_to_check = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy"
        ]

        for header in headers_to_check:
            result["security_headers"][header] = (
                response.headers.get(header, "Missing")
            )

    except Exception as error:
        result["error"] = str(error)

    return result
