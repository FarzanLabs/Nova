from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Relationship:
    source: str
    relation: str
    target: str
    source_type: str = "unknown"
    target_type: str = "unknown"


@dataclass
class InvestigationGraph:
    target: str
    relationships: list[Relationship] = field(
        default_factory=list
    )

    def add(
        self,
        source: str,
        relation: str,
        target: str,
        source_type: str = "unknown",
        target_type: str = "unknown",
    ) -> None:

        if not source or not target:
            return

        relationship = Relationship(
            source=source,
            relation=relation,
            target=target,
            source_type=source_type,
            target_type=target_type,
        )

        if relationship not in self.relationships:
            self.relationships.append(
                relationship
            )

    def nodes(self) -> list[str]:

        values = set()

        for item in self.relationships:
            values.add(item.source)
            values.add(item.target)

        return sorted(values)

    def to_dict(self) -> dict:

        return {
            "target": self.target,
            "nodes": self.nodes(),
            "relationships": [
                {
                    "source": item.source,
                    "relation": item.relation,
                    "target": item.target,
                    "source_type": item.source_type,
                    "target_type": item.target_type,
                }
                for item in self.relationships
            ],
        }