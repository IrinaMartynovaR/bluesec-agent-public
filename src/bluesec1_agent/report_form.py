"""Benign reports as a form of roles the model fills and the code assembles.

A legitimate activity is proven by who did it, what started it, what ran and what it
was for - the questions an analyst closes before calling an alert a false positive.
Left free, a benign report drifts toward whatever looked most technical (a handle
access, a script block, a logon record) and leaves out the account or the task that
actually make the activity authorized. So the model names one entity per role, the
code keeps only entities the investigation saw with fields that have values, drops a
built-in account (it proves nothing about authorization), and lists the roles in a
fixed order. A role nothing answers stays empty: a wrong item costs precision.
"""

from typing import Any

from bluesec1_agent.casefile import CaseFile
from bluesec1_agent.ids import resolve_id

MAX_FIELDS = 3
MAX_FORM_ITEMS = 4
MAX_SIGNAL_ANSWERS = 2
SLOTS = ("trigger", "account", "initiator", "purpose")
BUILTIN_SIDS = ("S-1-5-18", "S-1-5-19", "S-1-5-20")
BUILTIN_NAMES = ("system", "local service", "network service", "root")


def builtin_account(value: str) -> bool:
    """Whether an account name or SID is a built-in one (SYSTEM, LOCAL/NETWORK SERVICE)."""
    lowered = value.strip().lower()
    name = lowered.rsplit("\\", 1)[-1]
    return any(lowered.startswith(sid.lower()) for sid in BUILTIN_SIDS) or name in BUILTIN_NAMES


def identity_is_builtin(properties: dict[str, Any]) -> bool:
    """Whether an account entity is a built-in one, by SID or by name."""
    return any(
        builtin_account(str(properties[key]))
        for key in ("sid", "username", "name", "sam_account_name")
        if properties.get(key)
    )


def _slot(description: str) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "description": description,
        "properties": {
            "entity_id": {"type": "string"},
            "fields": {
                "type": "array",
                "items": {"type": "string"},
                "minItems": 1,
                "maxItems": MAX_FIELDS,
                "description": "The property fields whose values show it, most telling first.",
            },
            "why": {"type": "string", "minLength": 5},
        },
        "required": ["entity_id", "fields", "why"],
    }


LEGITIMACY_FORM_TOOL: dict[str, Any] = {
    "name": "legitimacy_form",
    "description": (
        "State why the activity is legitimate, one entity per question. Name an entity "
        "seen in this case (not a relation) and at most three of its property fields "
        "whose values prove the point. Leave a question out if nothing seen answers it."
    ),
    "parameters": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "trigger": _slot("What ran: the alerted entity and that it is the genuine article."),
            "account": _slot(
                "Who did it: the named person or service account entity it ran as, with "
                "its role, groups or description. Leave out a built-in account (SYSTEM, "
                "LOCAL SERVICE, NETWORK SERVICE): it says nothing about authorization."
            ),
            "initiator": _slot(
                "What started it: the scheduled task, service, parent process or the "
                "host the session came from."
            ),
            "purpose": _slot(
                "What it was for: the destination, package, policy, script, certificate, "
                "file or product the activity served."
            ),
            "signal_answers": {
                "type": "array",
                "maxItems": MAX_SIGNAL_ANSWERS,
                "description": "For each strong suspicious signal, the entity that answers it.",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "signal": {"type": "string", "minLength": 3},
                        **_slot("")["properties"],
                    },
                    "required": ["signal", "entity_id", "fields", "why"],
                },
            },
        },
        "required": ["trigger"],
    },
}

FORM_PROMPT = (
    "Write the benign report by calling legitimacy_form: who did it, what started it, "
    "what ran and what it was for. Answer each role with one entity seen in this case "
    "and at most three of its fields - the fields whose values prove the point. Use a "
    "different entity for each role, and leave a role out if nothing seen answers it: "
    "a wrong item costs more than an empty role."
)


def build_benign_report(
    form: dict[str, Any],
    case_file: CaseFile,
    signal_evidence: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    """Turn a filled form into finishing-tool arguments, keeping only what was seen.

    The roles come first in a fixed order (what ran, who, what started it, what for),
    then the form's answers to strong signals. Explanations checked when the verdict
    was derived fill places only when the form named nothing but the trigger: an item
    that does not prove the point costs more than an empty place.

    Args:
        form: Arguments of the `legitimacy_form` call.
        case_file: Everything the investigation established.
        signal_evidence: Verified signal explanations in legitimacy-evidence shape.

    Returns:
        Finishing-tool arguments for a benign submission, or None if no answer names an
        entity with the cited fields.
    """
    answers = [(slot, form.get(slot)) for slot in SLOTS]
    answers += [("signal", item) for item in form.get("signal_answers") or []]
    known = case_file.entities.keys() | case_file.ad_objects.keys()
    evidence: dict[str, list[str]] = {}
    reasons = []
    for slot, answer in answers:
        if not isinstance(answer, dict):
            continue
        entity_id = resolve_id(str(answer.get("entity_id", "")), known)
        if entity_id is None:
            continue
        values = case_file.entities.get(entity_id, {}).get(
            "properties"
        ) or case_file.ad_objects.get(entity_id, {})
        fields = [
            name
            for name in dict.fromkeys(answer.get("fields") or [])
            if values.get(name) not in (None, "", [], {})
        ][:MAX_FIELDS]
        if not fields:
            continue
        if slot == "account" and identity_is_builtin(values):
            continue
        if entity_id not in evidence and len(evidence) >= MAX_FORM_ITEMS:
            continue
        merged = evidence.setdefault(entity_id, [])
        merged += [name for name in fields if name not in merged]
        evidence[entity_id] = merged[:MAX_FIELDS]
        label = answer.get("signal") if slot == "signal" else slot
        reasons.append(f"{label}: {answer.get('why', '').strip()}")
    if not evidence:
        return None
    items: list[dict[str, Any]] = [
        {"anchor": "entity", "entity_id": entity_id, "property_fields": fields}
        for entity_id, fields in evidence.items()
    ][:MAX_FORM_ITEMS]
    for item in signal_evidence or [] if len(items) == 1 else []:
        anchor_id = item.get("entity_id") or item.get("relation_id")
        if len(items) >= 2:
            break
        if any((i.get("entity_id") or i.get("relation_id")) == anchor_id for i in items):
            continue
        items.append(
            {**item, "property_fields": list(item.get("property_fields") or [])[:MAX_FIELDS]}
        )
    return {
        "submission": {
            "verdict": "benign",
            "legitimacy_evidence": items[:MAX_FORM_ITEMS],
            "reasoning": "Legitimate activity. " + " ".join(reasons),
        }
    }
