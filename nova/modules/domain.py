from __future__ import annotations

import re
import socket

import dns.resolver
import httpx

from nova.core.models import ScanResult
from nova.modules.correlation import (
    InvestigationGraph,
)
from nova.modules.tls import inspect_tls


RECORD_TYPES = [
    "A",
    "AAAA",
    "MX",
    "NS",
    "TXT",
    "CNAME",
]


HEADERS = {
    "User-Agent": "Nova-OSINT/1.0"
}


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


def normalize_domain(domain: str) -> str:

    domain = domain.strip().lower()

    domain = re.sub(
        r"^https?://",
        "",
        domain,
    )

    domain = domain.split("/")[0]

    return domain.rstrip(".")


def scan_dns(
    domain: str,
    result: ScanResult,
    graph: InvestigationGraph,
):

    for record_type in RECORD_TYPES:

        try:

            answers = dns.resolver.resolve(
                domain,
                record_type,
                lifetime=5,
            )

            for answer in answers:

                value = answer.to_text().strip()

                if record_type == "MX":
                    value = value.rstrip(".")

                add(
                    result,
                    "DNS",
                    record_type,
                    value,
                    "DNS",
                )

                graph.add(
                    domain,
                    record_type,
                    value,
                    "domain",
                    "dns",
                )

        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout,
        ):

            continue

        except Exception as exc:

            add(
                result,
                "ERROR",
                f"DNS_{record_type}",
                exc,
                "DNS",
            )


def discover_subdomains(
    domain: str,
) -> list[str]:

    found = set()

    try:

        response = httpx.get(
            "https://crt.sh/",
            params={
                "q": f"%.{domain}",
                "output": "json",
            },
            headers=HEADERS,
            timeout=15,
        )

        response.raise_for_status()

        data = response.json()

        for item in data:

            names = item.get(
                "name_value",
                "",
            )

            for name in names.splitlines():

                name = (
                    name
                    .strip()
                    .lower()
                    .lstrip("*.")
                    .rstrip(".")
                )

                if not name:
                    continue

                if name == domain:
                    continue

                if name.endswith(
                    f".{domain}"
                ):
                    found.add(name)

    except Exception:
        pass

    return sorted(found)


def resolve_host(
    host: str,
) -> list[str]:

    addresses = set()

    try:

        results = socket.getaddrinfo(
            host,
            None,
        )

        for item in results:

            address = item[4][0]

            if address:
                addresses.add(address)

    except Exception:
        pass

    return sorted(addresses)


def inspect_web(
    host: str,
    result: ScanResult,
    graph: InvestigationGraph,
):

    try:

        response = httpx.get(
            f"https://{host}",
            headers=HEADERS,
            timeout=10,
            follow_redirects=True,
        )

        add(
            result,
            "HTTP",
            "status",
            response.status_code,
            "HTTPS",
        )

        add(
            result,
            "HTTP",
            "final_url",
            response.url,
            "HTTPS",
        )

        server = response.headers.get(
            "server"
        )

        if server:

            add(
                result,
                "HTTP",
                "server",
                server,
                "HTTPS",
            )

            graph.add(
                host,
                "uses",
                server,
                "host",
                "technology",
            )

        powered = response.headers.get(
            "x-powered-by"
        )

        if powered:

            add(
                result,
                "HTTP",
                "powered_by",
                powered,
                "HTTPS",
            )

    except Exception:
        pass


def scan_domain(
    domain: str,
) -> ScanResult:

    domain = normalize_domain(domain)

    result = ScanResult(
        target=domain
    )

    graph = InvestigationGraph(
        target=domain
    )

    add(
        result,
        "TARGET",
        "domain",
        domain,
        "Nova",
    )

    # DNS

    scan_dns(
        domain,
        result,
        graph,
    )

    # Certificate Transparency

    subdomains = discover_subdomains(
        domain
    )

    for subdomain in subdomains:

        add(
            result,
            "SUBDOMAIN",
            "host",
            subdomain,
            "crt.sh",
        )

        graph.add(
            domain,
            "has_subdomain",
            subdomain,
            "domain",
            "subdomain",
        )

    # Host resolution

    hosts = [
        domain,
        *subdomains,
    ]

    seen_ips = set()

    for host in hosts:

        addresses = resolve_host(
            host
        )

        for address in addresses:

            add(
                result,
                "INFRASTRUCTURE",
                "ip",
                address,
                "DNS",
            )

            graph.add(
                host,
                "resolves_to",
                address,
                "host",
                "ip",
            )

            seen_ips.add(address)

    # HTTPS / TLS

    tls_hosts = []

    for host in hosts:

        tls = inspect_tls(host)

        if tls.protocol:

            tls_hosts.append(host)

            add(
                result,
                "TLS",
                "protocol",
                tls.protocol,
                "TLS",
            )

            add(
                result,
                "TLS",
                "cipher",
                tls.cipher,
                "TLS",
            )

            add(
                result,
                "TLS",
                "subject",
                tls.subject,
                "TLS",
            )

            add(
                result,
                "TLS",
                "issuer",
                tls.issuer,
                "TLS",
            )

            for san in tls.san or []:

                add(
                    result,
                    "CERTIFICATE",
                    "san",
                    san,
                    "TLS",
                )

                graph.add(
                    host,
                    "certificate_contains",
                    san,
                    "host",
                    "certificate_name",
                )

    # HTTP technology

    inspect_web(
        domain,
        result,
        graph,
    )

    # Graph summary

    add(
        result,
        "CORRELATION",
        "nodes",
        len(graph.nodes()),
        "Nova",
    )

    add(
        result,
        "CORRELATION",
        "relationships",
        len(graph.relationships),
        "Nova",
    )

    return result