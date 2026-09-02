from __future__ import annotations

import httpx


HEADERS = {
    "User-Agent": "Nova-OSINT/1.0"
}


def lookup_asn(ip: str) -> dict:

    result = {
        "ip": ip,
        "asn": None,
        "name": None,
        "country": None,
        "prefix": None,
    }

    try:

        response = httpx.get(
            f"https://api.bgpview.io/ip/{ip}",
            headers=HEADERS,
            timeout=12,
        )

        if response.status_code != 200:
            return result

        data = response.json()

        prefixes = data.get(
            "data",
            {},
        ).get(
            "prefixes",
            [],
        )

        if not prefixes:
            return result

        prefix = prefixes[0]

        result["prefix"] = prefix.get(
            "prefix"
        )

        asns = prefix.get(
            "asn",
            {},
        )

        result["asn"] = asns.get(
            "asn"
        )

        result["name"] = asns.get(
            "name"
        )

        result["country"] = asns.get(
            "country_code"
        )

    except Exception:
        pass

    return result