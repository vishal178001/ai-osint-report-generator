import socket
import ssl
from datetime import datetime


def collect_ssl(domain):
    result = {
        "issuer": {},
        "subject": {},
        "serial_number": "",
        "version": None,
        "not_before": "",
        "not_after": "",
        "days_remaining": None,
        "error": ""
    }

    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(
                sock,
                server_hostname=domain
            ) as secure_sock:

                cert = secure_sock.getpeercert()

                result["issuer"] = dict(
                    item[0] for item in cert.get("issuer", [])
                )

                result["subject"] = dict(
                    item[0] for item in cert.get("subject", [])
                )

                result["serial_number"] = cert.get(
                    "serialNumber", ""
                )

                result["version"] = cert.get("version")

                result["not_before"] = cert.get(
                    "notBefore", ""
                )

                result["not_after"] = cert.get(
                    "notAfter", ""
                )

                expiry = datetime.strptime(
                    cert["notAfter"],
                    "%b %d %H:%M:%S %Y %Z"
                )

                result["days_remaining"] = (
                    expiry - datetime.utcnow()
                ).days

    except Exception as error:
        result["error"] = str(error)

    return result
