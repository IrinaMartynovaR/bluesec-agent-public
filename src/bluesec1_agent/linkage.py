"""How each entity the investigation opened is tied to the alert, as plain facts.

A report should be built from what the investigation found, not from what reads most
persuasively. This module ranks the opened entities by structural ties to the alert's
trigger - no knowledge of tasks, policies or attacks, only shared values and edges:

- a shared value: the trigger's command line or path names the entity, or one of the
  entity's fields contains the trigger's command line or path;
- a direct relation with the trigger;
- the same logon session;
- the same host.

The model sees the ranked list with the reason for each tie and decides what belongs
in the report.
"""

from typing import Any

from bluesec1_agent.casefile import CaseFile

MIN_SHARED = 8
MAX_LINKED = 10
TIES = ("shared value", "direct relation", "same session", "same host")


def _shared_value(trigger: dict[str, Any], properties: dict[str, Any]) -> str | None:
    """The field through which the entity and the trigger's command line share a value.

    Either the command line names one of the entity's values (a script path, a file,
    an address), or one of the entity's fields contains the whole command line (a task
    action, a service binary path). The trigger's own binary and its parent's path do
    not count: hundreds of processes share them.
    """
    cmdline = str(trigger.get("cmdline") or "").lower()
    if len(cmdline) < MIN_SHARED:
        return None
    common = {
        str(trigger.get(key) or "").lower()
        for key in ("image_path", "parent_image", "original_filename")
    }
    common |= {value.rsplit("\\", 1)[-1] for value in common}
    for name, value in properties.items():
        if not isinstance(value, str) or len(value) < MIN_SHARED:
            continue
        lowered = value.lower()
        if lowered in common or lowered.rsplit("\\", 1)[-1] in common:
            continue
        if lowered in cmdline or cmdline in lowered:
            return name
    return None


def linked_entities(case_file: CaseFile, trigger_ids: set[str]) -> list[str]:
    """Opened entities ranked by their strongest tie to the trigger, with the reason.

    Returns:
        Lines "id [type] label: tie (detail)", strongest ties first.
    """
    trigger_id = next(
        (
            entity_id
            for entity_id in trigger_ids
            if str(case_file.entities.get(entity_id, {}).get("type", "")).endswith("_process")
        ),
        None,
    )
    if trigger_id is None:
        return []
    trigger = case_file.entities[trigger_id].get("properties") or {}
    trigger_host = case_file.raw.get(trigger_id, {}).get("host_id")
    trigger_logon = str(trigger.get("logon_id") or "").lower()
    neighbours = {
        str(relation.get(end))
        for relation in case_file.relations.values()
        if trigger_id in (relation.get("source_id"), relation.get("target_id"))
        for end in ("source_id", "target_id")
    }
    ranked: list[tuple[int, str]] = []
    for entity_id, entry in case_file.entities.items():
        if entity_id in trigger_ids or not entry.get("properties"):
            continue
        properties = entry["properties"]
        field = _shared_value(trigger, properties)
        if field:
            tie, rank = f"shared value ({field})", 0
        elif entity_id in neighbours:
            tie, rank = "direct relation", 1
        elif (
            trigger_logon
            and str(properties.get("logon_id") or "").lower() == trigger_logon
            and trigger_host
            and case_file.raw.get(entity_id, {}).get("host_id") == trigger_host
        ):
            # A logon id names a session only on its own host.
            tie, rank = "same session", 2
        elif trigger_host and case_file.raw.get(entity_id, {}).get("host_id") == trigger_host:
            tie, rank = "same host", 3
        else:
            continue
        label = next(
            (
                str(properties[key])[:80]
                for key in ("task_name", "path", "image_path", "username", "hostname", "fqdn")
                if properties.get(key)
            ),
            "",
        )
        same_host = bool(trigger_host) and (
            case_file.raw.get(entity_id, {}).get("host_id") == trigger_host
        )
        where = "" if same_host or rank == 3 else ", other host"
        ranked.append(
            (
                rank * 2 + (0 if same_host else 1),
                f"{entity_id} [{entry.get('type')}] {label}: {tie}{where}",
            )
        )
    ranked.sort(key=lambda item: item[0])
    return [line for _, line in ranked[:MAX_LINKED]]
