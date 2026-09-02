import dns.resolver

from nova.core.models import ScanResult


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]


def scan_dns(domain: str, result: ScanResult) -> None:
    for record_type in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, record_type)

            for answer in answers:
                value = answer.to_text().strip()

                if not value:
                    continue

                result.add(
                    category="DNS",
                    key=record_type,
                    value=value,
                    source="DNS",
                )

        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout,
        ):
            continue

        except Exception as exc:
            result.add(
                category="ERROR",
                key=f"DNS_{record_type}",
                value=str(exc),
                source="DNS",
            )

