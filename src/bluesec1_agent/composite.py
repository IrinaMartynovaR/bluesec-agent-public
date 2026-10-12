"""Composite investigation tools built from the runtime's own calls.

The runtime exposes low-level graph access: one entity, one relation, a substring
search. Analysts think in larger units: "who started this and what did it start",
"where else does this hash run". A weak model spends many turns and mistakes
assembling those from raw JSON. These tools do the assembly in code with the same
runtime calls the model would make, every call counted, and return a compact table.
"""

from collections import Counter
from typing import Any

from bluesec1_agent.casefile import CaseFile, render_inline

PROCESS_CREATE = {"kind": "relation", "type": "win_process_create"}
MAX_TREE_DEPTH = 4
MAX_LISTED = 12

PROCESS_TREE_TOOL: dict[str, Any] = {
    "name": "process_tree",
    "description": (
        "Ancestry and children of a process in one table: walks the process-creation "
        "relations up to the root of the chain (parent, grandparent...) and lists the "
        "process's own children. Costs one runtime call per level plus one to open each "
        "ancestor not seen yet. Use it instead of opening parents one by one."
    ),
    "parameters": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "entity_id": {"type": "string", "description": "Id of a process entity."},
            "depth": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAX_TREE_DEPTH,
                "description": "Ancestor levels to walk up (default 3).",
            },
            "reasoning": {"type": "string", "minLength": 1},
        },
        "required": ["entity_id", "reasoning"],
    },
}
PREVALENCE_TOOL: dict[str, Any] = {
    "name": "prevalence",
    "description": (
        "Where else a value occurs: searches a hash, file name, command fragment, domain "
        "or address once and summarizes the matches by host, account and binary. Many "
        "hosts and accounts point to fleet software; one host or one account points to a "
        "targeted artifact. Costs one runtime call."
    ),
    "parameters": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "value": {"type": "string", "minLength": 5},
            "reasoning": {"type": "string", "minLength": 1},
        },
        "required": ["value", "reasoning"],
    },
}
COMPOSITE_TOOLS = {spec["name"]: spec for spec in (PROCESS_TREE_TOOL, PREVALENCE_TOOL)}


def describe_process(entity_id: str, case_file: CaseFile) -> str:
    """One line naming a process by what it ran, from the case file."""
    properties = case_file.entities.get(entity_id, {}).get("properties", {})
    if not properties:
        return f"{entity_id} (not opened)"
    cmdline = str(properties.get("cmdline") or "")
    if len(cmdline) > 160:
        cmdline = cmdline[:160] + "..."
    started = properties.get("start_time") or ""
    signals = case_file.entities.get(entity_id, {}).get("signals") or []
    detections = case_file.entities.get(entity_id, {}).get("detections") or []
    line = (
        f"{entity_id} {started} {properties.get('image_path', '?')} "
        f"cmd={render_inline(cmdline)} user={properties.get('user', '?')} "
        f"logon={properties.get('logon_id', '?')}"
    )
    if signals:
        line += f" signals={render_inline(signals)}"
    if detections:
        line += f" detections={render_inline(detections)}"
    return line


def creation_links(result: Any, entity_id: str) -> tuple[str | None, list[str]]:
    """Parent and children of a process from a process-creation search result."""
    parent = None
    children = []
    for node in (result or {}).get("results") or []:
        if not isinstance(node, dict) or node.get("type") != "win_process_create":
            continue
        if node.get("target_id") == entity_id and parent is None:
            parent = node.get("source_id")
        elif node.get("source_id") == entity_id:
            children.append(str(node.get("target_id")))
    return parent, children


def render_tree(
    ancestors: list[str], entity_id: str, children: list[str], case_file: CaseFile
) -> str:
    """Root first, then down to the process and its children."""
    lines = []
    for level, ancestor in enumerate(reversed(ancestors)):
        lines.append(f"{'  ' * level}- {describe_process(ancestor, case_file)}")
    depth = len(ancestors)
    lines.append(f"{'  ' * depth}- {describe_process(entity_id, case_file)} [ASKED]")
    for child in children[:MAX_LISTED]:
        lines.append(f"{'  ' * (depth + 1)}- {describe_process(child, case_file)}")
    if len(children) > MAX_LISTED:
        lines.append(f"{'  ' * (depth + 1)}- ... {len(children) - MAX_LISTED} more children")
    return "\n".join(lines)


def summarize_prevalence(value: str, result: Any, case_file: CaseFile) -> dict[str, Any]:
    """Matches of one search grouped by host, account, binary and type."""
    nodes = [node for node in (result or {}).get("results") or [] if isinstance(node, dict)]
    hosts: Counter[str] = Counter()
    users: Counter[str] = Counter()
    images: Counter[str] = Counter()
    types: Counter[str] = Counter()
    for node in nodes:
        types[str(node.get("type"))] += 1
        properties = node.get("properties") or {}
        host_id = node.get("host_id")
        if isinstance(host_id, str):
            host = case_file.entities.get(host_id, {}).get("properties", {})
            hosts[str(host.get("hostname") or host_id)] += 1
        if properties.get("user"):
            users[str(properties["user"])] += 1
        if properties.get("image_path"):
            images[str(properties["image_path"])] += 1
    summary: dict[str, Any] = {
        "value": value,
        "matches_on_this_page": len(nodes),
        "more_pages": bool((result or {}).get("next_page_id")),
        "by_type": dict(types),
        "distinct_hosts": len(hosts),
        "hosts": dict(hosts.most_common(MAX_LISTED)),
        "distinct_accounts": len(users),
        "accounts": dict(users.most_common(MAX_LISTED)),
        "binaries": dict(images.most_common(MAX_LISTED)),
        "ids": [node.get("id") for node in nodes][:MAX_LISTED],
    }
    return {key: item for key, item in summary.items() if item not in ({}, [])}
