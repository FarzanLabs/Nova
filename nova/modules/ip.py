from __future__ import annotations

import ipaddress

import httpx

from nova.core.models import ScanResult
from nova.modules.asn import lookup_asn
from nova.modules.enrichment import ip_geolocation


RDAP_URL = "https://rdap.org/ip/"


def add(
    result,
    category,
    key,
    value,
    source,
):

    if value is None:
        return

    value = str(value).strip()

    if not value:
        return

    result.add(
        category=category,
        key=key,
        value=value,
        source=source,
    )


def extract_entity_name(entity):

    vcard = entity.get(
        "vcardArray"
    )

    if not vcard or len(vcard) < 2:
        return None

    for field in vcard[1]:

        if len(field) >= 4:

            if field[0] == "fn":

                value = field[3]

                if isinstance(
                    value,
                    str,
                ):
                    return value

    return None


def scan_ip(ip: str) -> ScanResult:

    ip = ip.strip()

    result = ScanResult(
        target=ip
    )

    try:

        address = ipaddress.ip_address(ip)

    except ValueError:

        add(
            result,
            "ERROR",
            "validation",
            "Invalid IP address",
            "Nova",
        )

        return result

    ip = str(address)

    add(
        result,
        "TARGET",
        "ip",
        ip,
        "Nova",
    )

    add(
        result,
        "TARGET",
        "version",
        f"IPv{address.version}",
        "Nova",
    )

    if address.is_private:
        scope = "Private"

    elif address.is_loopback:
        scope = "Loopback"

    elif address.is_reserved:
        scope = "Reserved"

    elif address.is_link_local:
        scope = "Link-local"

    else:
        scope = "Public"

    add(
        result,
        "NETWORK",
        "scope",
        scope,
        "Nova",
    )

    # -------------------------
    # RDAP
    # -------------------------

    try:

        response = httpx.get(
            f"{RDAP_URL}{ip}",
            timeout=12,
            follow_redirects=True,
            headers={
                "User-Agent":
                "Nova-OSINT/1.0"
            },
        )

        response.raise_for_status()

        data = response.json()

        add(
            result,
            "NETWORK",
            "name",
            data.get("name"),
            "RDAP",
        )

        add(
            result,
            "NETWORK",
            "handle",
            data.get("handle"),
            "RDAP",
        )

        add(
            result,
            "NETWORK",
            "country",
            data.get("country"),
            "RDAP",
        )

        add(
            result,
            "NETWORK",
            "start_address",
            data.get("startAddress"),
            "RDAP",
        )

        add(
            result,
            "NETWORK",
            "end_address",
            data.get("endAddress"),
            "RDAP",
        )

        add(
            result,
            "NETWORK",
            "network_type",
            data.get("type"),
            "RDAP",
        )

        for entity in data.get(
            "entities",
            [],
        ):

            roles = entity.get(
                "roles",
                [],
            )

            name = extract_entity_name(
                entity
            )

            if not name:
                name = entity.get(
                    "handle"
                )

            if not name:
                continue

            for role in (
                "registrant",
                "administrative",
                "technical",
                "abuse",
            ):

                if role in roles:

                    add(
                        result,
                        "NETWORK",
                        role,
                        name,
                        "RDAP",
                    )

        for event in data.get(
            "events",
            [],
        ):

            action = event.get(
                "eventAction"
            )

            date = event.get(
                "eventDate"
            )

            if action and date:

                add(
                    result,
                    "RDAP",
                    action,
                    date,
                    "RDAP",
                )

    except Exception as exc:

        add(
            result,
            "ERROR",
            "rdap",
            exc,
            "RDAP",
        )

    # -------------------------
    # ASN
    # -------------------------

    asn = lookup_asn(ip)

    add(
        result,
        "ASN",
        "asn",
        asn.get("asn"),
        "BGPView",
    )

    add(
        result,
        "ASN",
        "name",
        asn.get("name"),
        "BGPView",
    )

    add(
        result,
        "ASN",
        "country",
        asn.get("country"),
        "BGPView",
    )

    add(
        result,
        "ASN",
        "prefix",
        asn.get("prefix"),
        "BGPView",
    )

    # -------------------------
    # Multi-source GEO
    # -------------------------

    geo = ip_geolocation(ip)

    add(
        result,
        "GEOLOCATION",
        "country",
        geo.country,
        "Nova consensus",
    )

    add(
        result,
        "GEOLOCATION",
        "region",
        geo.region,
        "Nova consensus",
    )

    add(
        result,
        "GEOLOCATION",
        "city",
        geo.city,
        "Nova consensus",
    )

    add(
        result,
        "GEOLOCATION",
        "latitude",
        geo.latitude,
        "Nova consensus",
    )

    add(
        result,
        "GEOLOCATION",
        "longitude",
        geo.longitude,
        "Nova consensus",
    )

    add(
        result,
        "GEOLOCATION",
        "timezone",
        geo.timezone,
        "Nova consensus",
    )

    add(
        result,
        "GEOLOCATION",
        "confidence",
        geo.geo_confidence,
        "Nova",
    )

    add(
        result,
        "GEOLOCATION",
        "consensus",
        geo.geo_consensus,
        "Nova",
    )

    add(
        result,
        "GEOLOCATION",
        "conflict",
        "YES"
        if geo.geo_conflict
        else "NO",
        "Nova",
    )

    # -------------------------
    # Individual providers
    # -------------------------

    for source in (
        geo.geo_sources or []
    ):

        prefix = source.source

        add(
            result,
            "GEO_SOURCE",
            f"{prefix}_country",
            source.country,
            prefix,
        )

        add(
            result,
            "GEO_SOURCE",
            f"{prefix}_country_code",
            source.country_code,
            prefix,
        )

        add(
            result,
            "GEO_SOURCE",
            f"{prefix}_region",
            source.region,
            prefix,
        )

        add(
            result,
            "GEO_SOURCE",
            f"{prefix}_city",
            source.city,
            prefix,
        )

        add(
            result,
            "GEO_SOURCE",
            f"{prefix}_latitude",
            source.latitude,
            prefix,
        )

        add(
            result,
            "GEO_SOURCE",
            f"{prefix}_longitude",
            source.longitude,
            prefix,
        )

        add(
            result,
            "GEO_SOURCE",
            f"{prefix}_organization",
            source.organization,
            prefix,
        )

    # -------------------------
    # Network enrichment
    # -------------------------

    add(
        result,
        "NETWORK",
        "isp",
        geo.isp,
        "Geolocation",
    )

    add(
        result,
        "NETWORK",
        "organization",
        geo.organization,
        "Geolocation",
    )

    add(
        result,
        "DNS",
        "reverse",
        geo.reverse_dns,
        "DNS",
    )

    # -------------------------
    # Warning
    # -------------------------

    if geo.geo_conflict:

        add(
            result,
            "WARNING",
            "geolocation",
            (
                "Geolocation providers disagree. "
                "Treat physical location as an estimate."
            ),
            "Nova",
        )

    return result