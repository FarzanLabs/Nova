from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass

import httpx


HEADERS = {
    "User-Agent": "Nova-OSINT/1.0"
}


@dataclass
class GeoSource:
    source: str
    country: str | None = None
    country_code: str | None = None
    region: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    timezone: str | None = None
    isp: str | None = None
    organization: str | None = None


@dataclass
class IPIntelligence:
    ip: str

    asn: str | None = None
    organization: str | None = None
    country: str | None = None
    city: str | None = None
    region: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    timezone: str | None = None
    isp: str | None = None
    reverse_dns: str | None = None

    geo_sources: list[GeoSource] | None = None
    geo_confidence: str = "Unknown"
    geo_conflict: bool = False
    geo_consensus: str | None = None


def safe_get_json(
    url: str,
    params=None,
    timeout: int = 12,
):
    try:

        response = httpx.get(
            url,
            params=params,
            headers=HEADERS,
            timeout=timeout,
            follow_redirects=True,
        )

        if response.status_code != 200:
            return None

        return response.json()

    except Exception:
        return None


def reverse_dns(ip: str) -> str | None:

    try:

        hostname = socket.gethostbyaddr(ip)[0]

        return hostname

    except Exception:

        return None


def lookup_ipwhois(
    ip: str,
) -> GeoSource | None:

    data = safe_get_json(
        f"https://ipwho.is/{ip}"
    )

    if not data:
        return None

    if data.get("success") is False:
        return None

    connection = data.get(
        "connection",
        {},
    ) or {}

    timezone = data.get(
        "timezone",
        {},
    ) or {}

    return GeoSource(
        source="ipwho.is",
        country=data.get("country"),
        country_code=data.get(
            "country_code"
        ),
        region=data.get("region"),
        city=data.get("city"),
        latitude=data.get("latitude"),
        longitude=data.get("longitude"),
        timezone=timezone.get("id"),
        isp=connection.get("isp"),
        organization=connection.get("org"),
    )


def lookup_ipapi(
    ip: str,
) -> GeoSource | None:

    data = safe_get_json(
        f"https://ipapi.co/{ip}/json/"
    )

    if not data:
        return None

    if data.get("error"):
        return None

    return GeoSource(
        source="ipapi.co",
        country=data.get("country_name"),
        country_code=data.get(
            "country_code"
        ),
        region=data.get("region"),
        city=data.get("city"),
        latitude=data.get("latitude"),
        longitude=data.get("longitude"),
        timezone=data.get("timezone"),
        isp=data.get("org"),
        organization=data.get("org"),
    )


def lookup_ip_api(
    ip: str,
) -> GeoSource | None:

    data = safe_get_json(
        f"https://ip-api.com/json/{ip}",
        params={
            "fields": (
                "status,message,country,"
                "countryCode,regionName,city,"
                "lat,lon,timezone,isp,org,as"
            )
        },
    )

    if not data:
        return None

    if data.get("status") != "success":
        return None

    return GeoSource(
        source="ip-api.com",
        country=data.get("country"),
        country_code=data.get(
            "countryCode"
        ),
        region=data.get("regionName"),
        city=data.get("city"),
        latitude=data.get("lat"),
        longitude=data.get("lon"),
        timezone=data.get("timezone"),
        isp=data.get("isp"),
        organization=data.get("org"),
    )


def choose_consensus(
    sources: list[GeoSource],
) -> tuple[str | None, str]:

    countries = {}

    for source in sources:

        code = (
            source.country_code
            or source.country
        )

        if not code:
            continue

        key = code.upper()

        countries[key] = (
            countries.get(key, 0) + 1
        )

    if not countries:
        return None, "Unknown"

    ranked = sorted(
        countries.items(),
        key=lambda item: item[1],
        reverse=True,
    )

    winner = ranked[0][0]
    votes = ranked[0][1]
    total = len(sources)

    if total == 1:
        confidence = "Low"

    elif votes == total:
        confidence = "High"

    elif votes >= 2:
        confidence = "Medium"

    else:
        confidence = "Low"

    return winner, confidence


def ip_geolocation(
    ip: str,
) -> IPIntelligence:

    info = IPIntelligence(
        ip=ip,
        geo_sources=[],
    )

    try:

        address = ipaddress.ip_address(ip)

        if (
            address.is_private
            or address.is_loopback
            or address.is_reserved
            or address.is_link_local
        ):
            return info

    except ValueError:

        return info

    sources = []

    # Provider 1
    source = lookup_ipwhois(ip)

    if source:
        sources.append(source)

    # Provider 2
    source = lookup_ipapi(ip)

    if source:
        sources.append(source)

    # Provider 3
    source = lookup_ip_api(ip)

    if source:
        sources.append(source)

    info.geo_sources = sources

    if not sources:
        info.reverse_dns = reverse_dns(ip)
        return info

    consensus, confidence = choose_consensus(
        sources
    )

    info.geo_consensus = consensus
    info.geo_confidence = confidence

    countries = {
        (
            source.country_code
            or source.country
            or ""
        ).upper()
        for source in sources
        if (
            source.country_code
            or source.country
        )
    }

    info.geo_conflict = len(
        countries
    ) > 1

    # Select the majority source.
    selected = None

    for source in sources:

        code = (
            source.country_code
            or source.country
            or ""
        ).upper()

        if code == consensus:
            selected = source
            break

    if selected is None:
        selected = sources[0]

    info.country = selected.country
    info.city = selected.city
    info.region = selected.region
    info.latitude = selected.latitude
    info.longitude = selected.longitude
    info.timezone = selected.timezone
    info.isp = selected.isp
    info.organization = selected.organization

    info.reverse_dns = reverse_dns(ip)

    return info