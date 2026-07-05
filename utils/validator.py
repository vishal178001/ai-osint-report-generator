import re


def validate_domain(domain):
    domain = domain.strip().lower()

    pattern = (
        r"^(?=.{1,253}$)"
        r"(?:[a-z0-9]"
        r"(?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"[a-z]{2,63}$"
    )

    return bool(re.fullmatch(pattern, domain))
