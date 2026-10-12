"""Competing hypotheses kept by the code, not only in the model's head.

An investigation goes wrong in two ways: it never asks a question (the attack next to
a browser alert is never considered), or it keeps asking one it cannot answer (the
"any other persistence?" tail). Writing hypotheses down fixes both: each one is a
question with a status, every step should move one of them, and the report waits
until each is resolved by evidence or explicitly dropped.
"""

from collections.abc import Collection
from typing import Any

from bluesec1_agent.ids import resolve_id

STATUSES = ("open", "supported", "refuted")
SIDES = ("legitimate", "malicious")
MAX_HYPOTHESES = 6

HYPOTHESES_TOOL: dict[str, Any] = {
    "name": "hypotheses",
    "description": (
        "Record or update the competing hypotheses of this case. Costs no runtime call. "
        "Keep at least one legitimate and one malicious explanation, including any "
        "suspicious activity next to the alert. Each hypothesis is open until evidence "
        "supports or refutes it; cite the entity ids that do."
    ),
    "parameters": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "items": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_HYPOTHESES,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "id": {"type": "string", "description": "Short label, e.g. H1."},
                        "statement": {"type": "string", "minLength": 5},
                        "status": {"enum": list(STATUSES)},
                        "side": {
                            "enum": list(SIDES),
                            "description": "Whether it explains the activity as "
                            "legitimate or as an attack.",
                        },
                        "evidence_ids": {"type": "array", "items": {"type": "string"}},
                        "next_check": {
                            "type": "string",
                            "description": "The one call that would decide it, if open.",
                        },
                    },
                    "required": ["id", "statement", "status"],
                },
            }
        },
        "required": ["items"],
    },
}


class HypothesisBoard:
    """The case's hypotheses and their status, checked against what was seen."""

    def __init__(self) -> None:
        """Start with no hypotheses."""
        self.items: dict[str, dict[str, Any]] = {}

    def update(self, items: list[dict[str, Any]], known: Collection[str]) -> dict[str, Any]:
        """Add or replace hypotheses; a resolved one needs evidence that was seen.

        Args:
            items: Hypotheses from the tool call.
            known: Ids of entities and relations in the case file.

        Returns:
            Feedback naming what was recorded and what was refused.
        """
        refused = []
        for item in items:
            label = str(item.get("id") or f"H{len(self.items) + 1}")
            evidence = [
                resolved
                for value in item.get("evidence_ids") or []
                if (resolved := resolve_id(str(value), known)) is not None
            ]
            status = item.get("status", "open")
            if status != "open" and not evidence:
                refused.append(
                    f"{label}: '{status}' needs evidence_ids of entities or relations seen "
                    "in this case; kept open"
                )
                status = "open"
            if label not in self.items and len(self.items) >= MAX_HYPOTHESES:
                refused.append(f"{label}: at most {MAX_HYPOTHESES} hypotheses; merge or drop one")
                continue
            self.items[label] = {
                "statement": item.get("statement", ""),
                "status": status,
                "evidence_ids": evidence,
                **({"next_check": item["next_check"]} if item.get("next_check") else {}),
                **({"side": item["side"]} if item.get("side") in SIDES else {}),
            }
        feedback: dict[str, Any] = {"status": "ok", "board": self.render()}
        if refused:
            feedback["refused"] = refused
        return feedback

    def open(self) -> list[str]:
        """Labels of hypotheses still open."""
        return [label for label, item in self.items.items() if item["status"] == "open"]

    def render(self) -> list[str]:
        """One line per hypothesis."""
        lines = []
        for label, item in self.items.items():
            line = f"{label} [{item['status']}] {item['statement']}"
            if item["evidence_ids"]:
                line += f" evidence={','.join(item['evidence_ids'])}"
            if item["status"] == "open" and item.get("next_check"):
                line += f" next: {item['next_check']}"
            lines.append(line)
        return lines
