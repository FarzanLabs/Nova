from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime


@dataclass
class CertificateInfo:
    hostname: str
    subject: str | None = None
    issuer: str | None = None
    serial_number: str | None = None
    version: int | None = None
    not_before: str | None = None
    not_after: str | None = None
    days_remaining: int | None = None
    san: list[str] | None = None


def flatten_name(name) -> str | None:

    values = []

    for group in name or []:

        for item in group:

            if len(item) >= 2:
                values.append(
                    f"{item[0]}={item[1]}"
                )

    if not values:
        return None

    return ", ".join(values)


def get_certificate(
    hostname: str,
    port: int = 443,
) -> CertificateInfo:

    result = CertificateInfo(
        hostname=hostname,
        san=[],
    )

    context = ssl.create_default_context()

    try:

        with socket.create_connection(
            (hostname, port),
            timeout=10,
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname,
            ) as tls:

                cert = tls.getpeercert()

                result.subject = flatten_name(
                    cert.get("subject")
                )

                result.issuer = flatten_name(
                    cert.get("issuer")
                )

                result.serial_number = (
                    cert.get("serialNumber")
                )

                result.version = cert.get(
                    "version"
                )

                result.not_before = cert.get(
                    "notBefore"
                )

                result.not_after = cert.get(
                    "notAfter"
                )

                for entry in cert.get(
                    "subjectAltName",
                    [],
                ):

                    if len(entry) >= 2:
                        kind, value = entry

                        if kind == "DNS":
                            result.san.append(
                                value
                            )

                if result.not_after:

                    try:

                        expiry = datetime.strptime(
                            result.not_after,
                            "%b %d %H:%M:%S %Y %Z",
                        )

                        result.days_remaining = (
                            expiry - datetime.utcnow()
                        ).days

                    except Exception:
                        pass

    except Exception:
        pass

    return result