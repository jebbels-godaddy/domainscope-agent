"""Public RDAP domain lookup client (IANA bootstrap + registry RDAP server)."""

import httpx

IANA_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"


class RdapLookupError(Exception):
    pass


def _get_rdap_base_url(tld: str, bootstrap: dict) -> str:
    tld = tld.lower()
    for entry in bootstrap.get("services", []):
        tlds, urls = entry[0], entry[1]
        if tld in [t.lower() for t in tlds]:
            return urls[0].rstrip("/") + "/"
    raise RdapLookupError(f"No RDAP server found for TLD: {tld}")


def lookup_domain(domain: str, client: httpx.Client | None = None) -> dict:
    domain = domain.strip().lower().rstrip(".")
    if "." not in domain:
        raise RdapLookupError(f"Invalid domain: {domain}")
    tld = domain.rsplit(".", 1)[-1]

    owns_client = client is None
    client = client or httpx.Client(timeout=10.0, follow_redirects=False)
    try:
        bootstrap_resp = client.get(IANA_BOOTSTRAP_URL)
        bootstrap_resp.raise_for_status()
        base_url = _get_rdap_base_url(tld, bootstrap_resp.json())

        rdap_resp = client.get(f"{base_url}domain/{domain}")
        if rdap_resp.status_code == 404:
            return {"domain": domain, "registered": False}
        rdap_resp.raise_for_status()
        data = rdap_resp.json()

        nameservers = [
            ns.get("ldhName") for ns in data.get("nameservers", []) if ns.get("ldhName")
        ]
        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
        dnssec = bool(data.get("secureDNS", {}).get("delegationSigned", False))

        return {
            "domain": domain,
            "registered": True,
            "status": data.get("status", []),
            "nameservers": nameservers,
            "registered_date": events.get("registration"),
            "expiration_date": events.get("expiration"),
            "last_changed_date": events.get("last changed"),
            "dnssec_signed": dnssec,
        }
    finally:
        if owns_client:
            client.close()
