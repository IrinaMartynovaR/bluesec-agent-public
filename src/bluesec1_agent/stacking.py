"""How common the key commands of a case are in this environment (stacking).

Administrators and attackers run the same commands; what differs is frequency and
context. Routine work repeats: the same command, launched the same way, on many hosts,
by the same service account, on a schedule. An intrusion is rare: one host, one
account, a command shape seen nowhere else. Before the verdict, the agent counts how
often the shape of each key command occurs in the graph - a history computed from the
data itself, without labels - so the assessment weighs the alert against what is
normal here rather than against general knowledge alone.
"""

import re
from typing import Any

from bluesec1_agent.casefile import CaseFile

MAX_STACKED = 3
MIN_FRAGMENT = 5
_VARIABLE = re.compile(r"[0-9a-f]{8}-[0-9a-f-]{27}|0x[0-9a-f]+|\d+", re.I)
_TOKEN = re.compile(r'[^\s"\']+')
STACK_REASONING = (
    "Stacking: how often this command occurs in the environment, on how many hosts and "
    "accounts, to tell routine work from a one-off."
)


def command_shape(image_path: str, cmdline: str) -> str:
    """The binary and command line with numbers, hex values and GUIDs blanked out."""
    return f"{image_path.lower()}|{_VARIABLE.sub('#', cmdline.lower())}"


def stable_fragment(properties: dict[str, Any]) -> str | None:
    """The longest stretch of the command line without digits, to search for the command.

    Numbers, ids and timestamps vary between runs of one command; the script path, a
    switch or the binary name do not. The stretch is a literal part of the command line,
    so a substring search finds every run. Falls back to the binary name.
    """
    cmdline = str(properties.get("cmdline") or "")
    pieces = [
        piece.strip(",;.-_")
        for token in _TOKEN.findall(cmdline)
        for piece in re.split(r"\d+", str(token))
    ]
    pieces = [piece for piece in pieces if len(piece) >= MIN_FRAGMENT]
    if pieces:
        return max(pieces, key=len)
    image = re.split(r"[\\/]", str(properties.get("image_path") or ""))[-1]
    return image if len(image) >= MIN_FRAGMENT else None


def key_processes(case_file: CaseFile, trigger_ids: set[str]) -> list[str]:
    """The trigger process first, then processes behind strong signals."""
    strong = [signal.split(":", 1)[0] for signal in case_file.strong_signals()]
    ordered = [*trigger_ids, *strong]
    chosen = []
    for entity_id in dict.fromkeys(ordered):
        entry = case_file.entities.get(entity_id, {})
        if str(entry.get("type", "")).endswith("_process") and entry.get("properties"):
            chosen.append(entity_id)
    return chosen[:MAX_STACKED]


def summarize_stack(entity_id: str, case_file: CaseFile, fragment: str, result: Any) -> str:
    """One line: how many processes share this command's shape, where and when."""
    properties = case_file.entities.get(entity_id, {}).get("properties", {})
    shape = command_shape(str(properties.get("image_path", "")), str(properties.get("cmdline", "")))
    matches = []
    for node in (result or {}).get("results") or []:
        if not isinstance(node, dict) or not str(node.get("type", "")).endswith("_process"):
            continue
        node_properties = node.get("properties") or {}
        node_shape = command_shape(
            str(node_properties.get("image_path", "")), str(node_properties.get("cmdline", ""))
        )
        if node_shape == shape:
            matches.append(node)
    hosts = {str(node.get("host_id")) for node in matches if node.get("host_id")}
    accounts = {str((node.get("properties") or {}).get("user")) for node in matches}
    times = sorted(
        str((node.get("properties") or {}).get("start_time") or (node.get("timestamps") or [""])[0])
        for node in matches
    )
    more = "+" if (result or {}).get("next_page_id") else ""
    cmdline = str(properties.get("cmdline", ""))[:120]
    if len(matches) <= 1:
        return (
            f"- {entity_id} {cmdline!r}: no other run of this command shape found "
            f"(searched {fragment!r})"
        )
    span = f", from {times[0]} to {times[-1]}" if times and times[0] else ""
    return (
        f"- {entity_id} {cmdline!r}: {len(matches)}{more} runs of this command shape on "
        f"{len(hosts)} host(s) by {len(accounts - {'None'})} account(s){span}"
    )
