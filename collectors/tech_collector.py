import requests
from bs4 import BeautifulSoup


def collect_technologies(domain):
    result = {
        "url": "",
        "server": "",
        "powered_by": "",
        "technologies": [],
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
        result["server"] = response.headers.get("Server", "")
        result["powered_by"] = response.headers.get(
            "X-Powered-By", ""
        )

        soup = BeautifulSoup(response.text, "html.parser")

        technologies = set()

        html = response.text.lower()

        if "wp-content" in html or "wordpress" in html:
            technologies.add("WordPress")

        if "drupal" in html:
            technologies.add("Drupal")

        if "joomla" in html:
            technologies.add("Joomla")

        if "react" in html:
            technologies.add("React")

        if "vue.js" in html or "vue.min.js" in html:
            technologies.add("Vue.js")

        if "angular" in html:
            technologies.add("Angular")

        if "bootstrap" in html:
            technologies.add("Bootstrap")

        if "jquery" in html:
            technologies.add("jQuery")

        generator = soup.find(
            "meta",
            attrs={"name": "generator"}
        )

        if generator and generator.get("content"):
            technologies.add(generator.get("content"))

        server = result["server"].lower()

        if "cloudflare" in server:
            technologies.add("Cloudflare")

        if "nginx" in server:
            technologies.add("Nginx")

        if "apache" in server:
            technologies.add("Apache")

        result["technologies"] = sorted(technologies)

    except Exception as error:
        result["error"] = str(error)

    return result
