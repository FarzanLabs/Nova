from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Finding:
    category: str
    key: str
    value: Any
    source: str = "local"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "key": self.key,
            "value": self.value,
            "source": self.source,
            "timestamp": self.timestamp,
        }


@dataclass
class ScanResult:
    target: str
    findings: list[Finding] = field(default_factory=list)

    def add(
        self,
        category: str,
        key: str,
        value: Any,
        source: str = "local",
    ) -> None:
        self.findings.append(
            Finding(
                category=category,
                key=key,
                value=value,
                source=source,
            )
        )

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "findings": [finding.to_dict() for finding in self.findings],
        }