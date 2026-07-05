from utils.validator import validate_domain


def test_valid_domains():
    assert validate_domain("example.com") is True
    assert validate_domain("google.com") is True
    assert validate_domain("sub.example.com") is True


def test_invalid_domains():
    assert validate_domain("not a domain") is False
    assert validate_domain("") is False
    assert validate_domain("http://example.com") is False
