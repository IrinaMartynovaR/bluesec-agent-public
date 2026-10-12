"""Turn the model's chain assessment into a verdict the code can stand behind.

The model describes the chain; the code only accepts what the case file supports.
Both directions are checked the same way: an attack stage counts only if it names
entities the investigation actually saw, and a legitimate explanation counts only
if it cites fields that exist and hold values on the entity it talks about. The
verdict then follows by rule, so neither suspicious facts nor legitimacy can be
asserted without evidence.
"""

import re
from dataclasses import dataclass, field
from typing import Any

from bluesec1_agent.casefile import CaseFile
from bluesec1_agent.ids import resolve_id

_ENTITY_SIGNAL = re.compile(r"^([^\s:]+): (.+)$")
_ENDPOINT = re.compile(r"external endpoint (\S+)")
# Fields that make two processes the same behaviour: an explanation of one applies to
# every sibling that ran the same binary, from the same parent, as the same account,
# with the same command line (repeated admin sessions, scheduled runs).
BEHAVIOUR_FIELDS = ("image_path", "parent_image", "user", "cmdline")


@dataclass
class ChainDecision:
    """Verdict with the evidence the code accepted and what it could not."""

    verdict: str
    grounded_stages: list[dict[str, Any]] = field(default_factory=list)
    verified_explanations: list[dict[str, Any]] = field(default_factory=list)
    rejected: list[str] = field(default_factory=list)
    unexplained_signals: list[str] = field(default_factory=list)

    def artifact_candidates(self, case_file: CaseFile) -> list[str]:
        """Entities of accepted stages and of unexplained signals."""
        ids = [
            entity_id for stage in self.grounded_stages for entity_id in stage.get("entity_ids", [])
        ]
        ids += [signal.split(":", 1)[0] for signal in self.unexplained_signals]
        return [entity_id for entity_id in dict.fromkeys(ids) if entity_id in case_file.entities]

    def evidence_candidates(self, case_file: CaseFile | None = None) -> list[dict[str, Any]]:
        """Accepted explanations in the finishing tool's legitimacy-evidence shape."""
        candidates = []
        for item in self.verified_explanations:
            if case_file is not None and item["entity_id"] in case_file.relations:
                candidates.append(
                    {
                        "anchor": "relation",
                        "relation_id": item["entity_id"],
                        "property_fields": item["property_fields"],
                    }
                )
            else:
                candidates.append(
                    {
                        "anchor": "entity",
                        "entity_id": item["entity_id"],
                        "property_fields": item["property_fields"],
                    }
                )
        return candidates

    def summary(self) -> dict[str, Any]:
        """Compact record for trajectories and prompts."""
        return {
            "verdict": self.verdict,
            "accepted_stages": len(self.grounded_stages),
            "accepted_explanations": len(self.verified_explanations),
            "rejected": self.rejected,
            "unexplained_signals": self.unexplained_signals,
            "chain_entities": sorted(self.chain_entities()),
        }

    def chain_entities(self) -> set[str]:
        """Entities the accepted stages and unexplained signals put in the attack chain."""
        ids = {
            entity_id for stage in self.grounded_stages for entity_id in stage.get("entity_ids", [])
        }
        return ids | {signal.split(":", 1)[0] for signal in self.unexplained_signals}


def decide(
    assessment: dict[str, Any],
    case_file: CaseFile,
    draft_verdict: str | None = None,
) -> ChainDecision:
    """Check the assessment against the case file and derive the verdict.

    Malicious if any attack stage is grounded in seen entities, or if a strong
    signal is neither part of a grounded stage nor explained with verified fields.
    An explanation of a process also covers its exact repeats (same binary, parent,
    account and command line). Benign otherwise.

    Unexplained signals alone do not overturn a benign conclusion the investigation
    reached: with no grounded attack stage there is no attacker step to point to, so
    the draft verdict stands and the signals stay listed as open doubts. In practice
    runs that override was wrong in 8 of 10 cases.

    Args:
        assessment: Arguments of the `assess_chain` call.
        case_file: Everything the investigation established.
        draft_verdict: The verdict of the report the model proposed, if any.

    Returns:
        The decision with accepted and rejected claims.
    """
    known = case_file.entities.keys() | case_file.relations.keys()
    decision = ChainDecision(verdict="benign")

    for stage in assessment.get("stages", []):
        ids = [
            resolved
            for entity_id in stage.get("entity_ids", [])
            if (resolved := resolve_id(entity_id, known)) is not None
        ]
        if ids:
            decision.grounded_stages.append({**stage, "entity_ids": ids})
        else:
            decision.rejected.append(
                f"stage {stage.get('tactic')} names no entity seen in the graph"
            )

    for item in assessment.get("signal_explanations", []):
        resolved = resolve_id(
            str(item.get("entity_id", "")), case_file.entities.keys() | case_file.relations.keys()
        )
        if resolved is not None:
            item = {**item, "entity_id": resolved}
        problem = _explanation_problem(item, case_file)
        if problem:
            decision.rejected.append(problem)
        else:
            decision.verified_explanations.append(item)

    covered = {
        entity_id for stage in decision.grounded_stages for entity_id in stage["entity_ids"]
    } | {item["entity_id"] for item in decision.verified_explanations}
    # A relation explains the entities it connects: a logon's type and source explain
    # the session's processes only through the account and host it links.
    for item in decision.verified_explanations:
        if relation := case_file.relations.get(item["entity_id"]):
            covered |= {relation.get("source_id"), relation.get("target_id")}
    texts = " ".join(
        [stage.get("evidence", "") for stage in decision.grounded_stages]
        + [
            item.get("signal", "") + " " + item.get("explanation", "")
            for item in decision.verified_explanations
        ]
    )
    explained_behaviours = {
        behaviour
        for item in decision.verified_explanations
        if (behaviour := _behaviour(item["entity_id"], case_file)) is not None
    }
    for signal in case_file.strong_signals():
        entity_match = _ENTITY_SIGNAL.match(signal)
        if entity_match and entity_match.group(1) in case_file.entities:
            entity_id = entity_match.group(1)
            if entity_id not in covered and (
                _behaviour(entity_id, case_file) not in explained_behaviours
            ):
                decision.unexplained_signals.append(signal)
        elif (endpoint := _ENDPOINT.search(signal)) and endpoint.group(1) not in texts:
            decision.unexplained_signals.append(signal)

    if decision.grounded_stages or (decision.unexplained_signals and draft_verdict != "benign"):
        decision.verdict = "malicious"
    return decision


def _behaviour(entity_id: str, case_file: CaseFile) -> tuple[str, ...] | None:
    """What a process did, as the fields shared by repeats of the same activity.

    Returns None unless every field has a value, so a process with an unknown
    command line or parent never borrows another one's explanation.
    """
    entry = case_file.entities.get(entity_id, {})
    properties = entry.get("properties") or {}
    values = tuple(str(properties.get(name) or "").lower() for name in BEHAVIOUR_FIELDS)
    if not str(entry.get("type", "")).endswith("_process") or not all(values):
        return None
    return values


def _explanation_problem(item: dict[str, Any], case_file: CaseFile) -> str | None:
    """Why a legitimacy explanation cannot be accepted, or None."""
    entity_id = str(item.get("entity_id"))
    properties = case_file.entities.get(entity_id, {}).get("properties") or (
        case_file.relations.get(entity_id, {}).get("properties")
    )
    if not properties:
        return f"explanation for {entity_id} cites an object whose properties were never seen"
    fields = item.get("property_fields") or []
    missing = [name for name in fields if name not in properties]
    if not fields or missing:
        return f"explanation for {entity_id} cites fields without values: {missing or 'none'}"
    return None
