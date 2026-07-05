import subprocess
import re


def collect_theharvester(domain):
    command = [
        "theHarvester",
        "-d", domain,
        "-b", "crtsh"
    ]

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120
        )

        output = process.stdout

        all_emails = re.findall(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
            output
        )

        emails = sorted(set(
            email for email in all_emails
            if email.lower().endswith("@" + domain.lower())
        ))

        ips = sorted(set(re.findall(
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            output
        )))

        hosts = sorted(set(re.findall(
            rf'\b(?:[A-Za-z0-9-]+\.)+{re.escape(domain)}\b',
            output,
            re.IGNORECASE
        )))

        return {
            "source": "crtsh",
            "return_code": process.returncode,
            "emails": emails,
            "hosts": hosts,
            "ips": ips,
            "error": process.stderr.strip()
        }

    except Exception as error:
        return {
            "source": "crtsh",
            "return_code": -1,
            "emails": [],
            "hosts": [],
            "ips": [],
            "error": str(error)
        }
