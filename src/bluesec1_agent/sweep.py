"""Survey what else ran in the alert's logon session and on its host around the alert.

An alert names one process, but the attack is often next to it rather than in it: a
browser or service alert can sit beside an Office macro that spawned an encoded
PowerShell on the same host. An analyst's first move is the host timeline, so the
agent opens it before the model's first turn, with the same search tool the model
uses, and shows the processes as one compact table. The table states facts only;
which entries matter is left to the model, the signals and the knowledge base.
"""

import re
from datetime import datetime, timedelta
from typing import Any

from bluesec1_agent.casefile import CaseFile, render_inline

# Around the alert's own activity; long-running triggers are capped so the first
# pages stay close to the alert.
SWEEP_BEFORE = timedelta(hours=1)
SWEEP_AFTER = timedelta(hours=1)
SWEEP_MAX_SPAN = timedelta(hours=6)
PROCESS_TYPES = {"windows": "windows_process", "linux": "linux_process"}
MAX_CMDLINE_CHARS = 220
SWEEP_REASONING = (
    "Host timeline: which processes ran on the alert's host around the alert time, so "
    "activity next to the trigger is not missed."
)


def sweep_arguments(alert: dict[str, Any]) -> dict[str, Any] | None:
    """Search arguments listing the processes on the alert host around the alert.

    Args:
        alert: Compacted alert with `trigger_entities`.

    Returns:
        Arguments for the search tool, or None when the alert names no host or time.
    """
    entities = [
        entity for entity in alert.get("trigger_entities") or [] if isinstance(entity, dict)
    ]
    host = next((entity for entity in entities if entity.get("type") == "host"), None)
    if host is None or not isinstance(host.get("id"), str):
        return None
    platform = str((host.get("properties") or {}).get("platform", "windows")).lower()
    process_type = PROCESS_TYPES.get(platform)
    times = sorted(
        parsed
        for entity in entities
        if entity is not host
        for value in entity.get("timestamps") or []
        if (parsed := _parse_time(value)) is not None
    )
    if process_type is None or not times:
        return None
    start = times[0] - SWEEP_BEFORE
    end = min(times[-1] + SWEEP_AFTER, start + SWEEP_MAX_SPAN)
    return {
        "reasoning": SWEEP_REASONING,
        "query": host["id"],
        "scope": {"kind": "entity", "type": process_type},
        "time_window": {"from": start.isoformat(), "to": end.isoformat()},
    }


# Activity just before the trigger's first event still counts as "after": clocks and
# event ordering are not exact.
SPLIT_MARGIN = timedelta(minutes=5)


def split_window(arguments: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """The sweep window as two views: from the trigger's start on, then the hour before.

    Search results come back in time order, one page at a time. On a busy session the
    first page of the whole window is spent on what ran an hour before the alert; what
    the trigger led to, or ran next to it, never shows. Asking for the later part first
    puts that on the first page, and the earlier hour, the trigger's context, second.
    """
    window = arguments["time_window"]
    start = _parse_time(window["from"])
    end = _parse_time(window["to"])
    if start is None or end is None:
        return [("around", arguments)]
    pivot = start + SWEEP_BEFORE - SPLIT_MARGIN
    after = {**arguments, "time_window": {"from": pivot.isoformat(), "to": end.isoformat()}}
    before = {**arguments, "time_window": {"from": start.isoformat(), "to": pivot.isoformat()}}
    return [("from the trigger's start on", after), ("in the hour before", before)]


def session_query(alert: dict[str, Any]) -> str | None:
    """Logon id of the trigger process, which names its logon session.

    Processes of one session share it: an interactive user's browser and the Office
    macro next to it, or a service account's web server and the shell it spawned,
    while background services of other sessions are left out.
    """
    for entity in alert.get("trigger_entities") or []:
        if not isinstance(entity, dict) or entity.get("type") == "host":
            continue
        logon_id = (entity.get("properties") or {}).get("logon_id")
        # Search needs at least 5 characters; shorter ids cannot be searched.
        if isinstance(logon_id, str) and len(logon_id) >= 5:
            return logon_id
    return None


def render_sweep(
    results: list[dict[str, Any]],
    case_file: CaseFile,
    trigger_ids: set[str],
) -> list[str]:
    """One line per process: when, what, from where, by whom, and attached facts.

    Args:
        results: Process entities returned by the sweep searches, in time order.
        case_file: Case file that already observed them, for signals and detections.
        trigger_ids: Entities named by the alert, marked in the table.

    Returns:
        Table lines.
    """
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for node in results:
        if not isinstance(node.get("id"), str):
            continue
        properties = node.get("properties") or {}
        # Repeats of one command (builds, polling, helpers) differ only in numbers and
        # ids; the alert's own entity and anything with a signal always stand alone.
        key = (
            str(properties.get("image_path", "")).lower(),
            _shape(str(properties.get("cmdline", ""))),
        )
        if node["id"] in trigger_ids or case_file.entities.get(node["id"], {}).get("signals"):
            key = (node["id"], "")
        groups.setdefault(key, []).append(node)
    lines = []
    for members in groups.values():
        node = members[0]
        entity_id = node["id"]
        properties = node.get("properties") or {}
        timestamps = node.get("timestamps") or []
        started = properties.get("start_time") or (timestamps[0] if timestamps else "?")
        cmdline = str(properties.get("cmdline", ""))
        if len(cmdline) > MAX_CMDLINE_CHARS:
            cmdline = cmdline[:MAX_CMDLINE_CHARS] + "..."
        line = (
            f"- {entity_id} {started} {properties.get('image_path', '?')} "
            f"cmd={render_inline(cmdline)} parent={properties.get('parent_image', '?')} "
            f"user={properties.get('user', '?')}"
        )
        if entity_id in trigger_ids:
            line += " [ALERT]"
        entry = case_file.entities.get(entity_id, {})
        if signals := entry.get("signals"):
            line += f" signals={render_inline(signals)}"
        if detections := entry.get("detections"):
            line += f" detections={render_inline(detections)}"
        if len(members) > 1:
            last = members[-1]
            last_time = (last.get("properties") or {}).get("start_time") or (
                (last.get("timestamps") or ["?"])[0]
            )
            line += f" [x{len(members)} similar until {last_time}, e.g. also {last['id']}]"
        lines.append(line)
    return lines


_VARIABLE = re.compile(r"[0-9a-f]{8}-[0-9a-f-]{27}|0x[0-9a-f]+|\d+", re.I)


def _shape(cmdline: str) -> str:
    """A command line with numbers, hex values and GUIDs blanked out."""
    return _VARIABLE.sub("#", cmdline.lower())


def _parse_time(value: Any) -> datetime | None:
    """ISO timestamp, or None."""
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


LOGON_SCOPE = {"kind": "relation", "type": "logged_on_to"}
USER_TYPES = {"windows": "windows_user", "linux": "linux_user"}
LOGON_REASONING = (
    "Logon context: who logged on to the alert host and from where, and which hosts the "
    "alert's account logged on to, so the entry point and the spread are not missed."
)


def alert_host(alert: dict[str, Any]) -> dict[str, Any] | None:
    """The host entity among the alert's trigger entities."""
    return next(
        (
            entity
            for entity in alert.get("trigger_entities") or []
            if isinstance(entity, dict) and entity.get("type") == "host"
        ),
        None,
    )


def account_query(alert: dict[str, Any]) -> tuple[str, str] | None:
    """Search query and entity type that find the account the trigger process ran as."""
    host = alert_host(alert)
    platform = str(((host or {}).get("properties") or {}).get("platform", "windows")).lower()
    for entity in alert.get("trigger_entities") or []:
        properties = entity.get("properties") or {} if isinstance(entity, dict) else {}
        # The SID is unique; a bare user name may match unrelated values.
        value = properties.get("user_sid") or str(properties.get("user") or "").split("\\")[-1]
        if isinstance(value, str) and len(value) >= 5 and platform in USER_TYPES:
            return value, USER_TYPES[platform]
    return None


def render_logons(relations: list[dict[str, Any]], case_file: CaseFile, anchor: str) -> list[str]:
    """One line per logon: when, who, where, how and from which address.

    Args:
        relations: `logged_on_to` relations from a search.
        case_file: Case file with any account and host names already seen.
        anchor: The host or account the search was about, marked as "this".
    """
    lines = []
    for relation in relations:
        if relation.get("type") != "logged_on_to":
            continue
        logon = relation.get("logon_properties") or {}
        lines.append(
            f"- {relation.get('id')} {relation.get('timestamp', '?')} "
            f"{_name(relation.get('source_id'), case_file, anchor)} -> "
            f"{_name(relation.get('target_id'), case_file, anchor)} "
            f"type={logon.get('logon_type', '?')} from={logon.get('source_ip', '-')}"
        )
    return lines


def _name(entity_id: Any, case_file: CaseFile, anchor: str) -> str:
    """Entity id with its known host or account name."""
    if entity_id == anchor:
        return f"{entity_id} (this)"
    properties = case_file.entities.get(str(entity_id), {}).get("properties", {})
    label = next(
        (properties[key] for key in ("hostname", "username", "ip") if properties.get(key)), None
    )
    return f"{entity_id} ({label})" if label else str(entity_id)
