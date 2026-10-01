import httpx
import pytest

from domainscope_agent.rdap_client import lookup_domain, RdapLookupError

BOOTSTRAP_BODY = {
    "services": [
        [["com"], ["https://rdap.verisign.com/com/v1/"]],
    ]
}


def test_lookup_domain_registered():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "data.iana.org":
            return httpx.Response(200, json=BOOTSTRAP_BODY)
        assert request.url.path == "/com/v1/domain/example.com"
        return httpx.Response(
            200,
            json={
                "status": ["active"],
                "nameservers": [
                    {"ldhName": "a.iana-servers.net"},
                    {"ldhName": "b.iana-servers.net"},
                ],
                "events": [
                    {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
                    {"eventAction": "expiration", "eventDate": "2026-08-13T04:00:00Z"},
                ],
                "secureDNS": {"delegationSigned": True},
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = lookup_domain("example.com", client=client)

    assert result["registered"] is True
    assert result["status"] == ["active"]
    assert result["nameservers"] == ["a.iana-servers.net", "b.iana-servers.net"]
    assert result["registered_date"] == "1995-08-14T04:00:00Z"
    assert result["expiration_date"] == "2026-08-13T04:00:00Z"
    assert result["dnssec_signed"] is True


def test_lookup_domain_not_registered():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "data.iana.org":
            return httpx.Response(200, json=BOOTSTRAP_BODY)
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = lookup_domain("doesnotexist-xyz123.com", client=client)

    assert result == {"domain": "doesnotexist-xyz123.com", "registered": False}


def test_lookup_domain_unknown_tld():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"services": []})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(RdapLookupError):
        lookup_domain("example.zzz", client=client)


def test_lookup_domain_rejects_bare_tld():
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    with pytest.raises(RdapLookupError):
        lookup_domain("com", client=client)
