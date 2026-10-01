from domainscope_agent.domain_lookup_executor import format_lookup_result


def test_format_lookup_result_registered():
    result = {
        "domain": "example.com",
        "registered": True,
        "status": ["active"],
        "nameservers": ["a.iana-servers.net", "b.iana-servers.net"],
        "registered_date": "1995-08-14T04:00:00Z",
        "expiration_date": "2026-08-13T04:00:00Z",
        "last_changed_date": None,
        "dnssec_signed": True,
    }
    text = format_lookup_result(result)
    assert "example.com" in text
    assert "a.iana-servers.net" in text
    assert "DNSSEC: signed" in text


def test_format_lookup_result_not_registered():
    result = {"domain": "doesnotexist-xyz123.com", "registered": False}
    text = format_lookup_result(result)
    assert "not registered" in text.lower()
