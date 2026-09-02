from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass


@dataclass
class TLSInfo:
    hostname: str
    port: int = 443
    protocol: str | None = None
    cipher: str | None = None
    subject: str | None = None
    issuer: str | None = None
    serial_number: str | None = None
    san: list[str] | None = None


def flatten_name(value) -> str | None:

    parts = []

    for group in value or []:

        for item in group:

            if len(item) >= 2:
                parts.append(
                    f"{item[0]}={item[1]}"
                )

    return ", ".join(parts) if parts else None


def inspect_tls(
    hostname: str,
    port: int = 443,
) -> TLSInfo:

    result = TLSInfo(
        hostname=hostname,
        port=port,
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

                result.protocol = (
                    tls.version()
                )

                cipher = tls.cipher()

                if cipher:
                    result.cipher = cipher[0]

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

    except Exception:
        pass

    return result