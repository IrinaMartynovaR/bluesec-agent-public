import json
from collections import Counter
from typing import Any

from bluesec1_agent.signals import STRONG_SIGNAL_MARKERS, entity_signals, is_external, lookalike

MAX_VALUE_CHARS = 400
# Connections to one external endpoint from which repetition looks like beaconing.
BEACON_MIN_CONNECTIONS = 5
MAX_LOOKALIKES = 3
EMPTY_VALUES: tuple[Any, ...] = (None, "", [], {})
# Some runtime records carry a generator marker saying they exist only in the scenario's
# ground truth. That is a property of the benchmark, not evidence an analyst would have,
# so it never reaches the model.
GROUND_TRUTH_MARKER = "ground_truth_only"
# Searches listed in the coverage section of the case file.
MAX_COVERAGE = 25


def compact(value: Any) -> Any:
    """Drop empty fields and decode embedded JSON before a payload reaches the LLM.

    Graph objects carry dozens of null properties; removing them roughly halves
    the context without losing evidence. Property names that do carry a value
    stay intact, so the model can still cite them in the final report.

    Args:
        value: Tool result or alert, possibly a JSON-encoded string.

    Returns:
        The same structure without null, empty-string, empty-list or empty-dict fields,
        and without the benchmark's ground-truth marker in `log_sources`.
    """
    if isinstance(value, str):
        stripped = value.strip()
        if stripped[:1] in {"{", "["}:
            try:
                return compact(json.loads(stripped))
            except json.JSONDecodeError:
                return value
        return value
    if isinstance(value, dict):
        cleaned = {
            key: compact(_without_marker(item) if key == "log_sources" else item)
            for key, item in value.items()
        }
        return {key: item for key, item in cleaned.items() if item not in EMPTY_VALUES}
    if isinstance(value, list):
        return [compact(item) for item in value if item not in EMPTY_VALUES]
    return value


class CaseFile:
    """Deterministic memory of every graph object the investigation has touched.

    Old raw tool results are dropped from the conversation to keep the context
    small; the case file keeps what they established in a dense form.
    """

    def __init__(self) -> None:
        """Start an empty case file."""
        self.entities: dict[str, dict[str, Any]] = {}
        self.relations: dict[str, dict[str, Any]] = {}
        self.last_entities: list[str] = []
        # Full compacted objects, so a repeated lookup can be answered without a call.
        self.raw: dict[str, dict[str, Any]] = {}
        # Active Directory objects are not graph entities, but they are evidence.
        self.ad_objects: dict[str, dict[str, Any]] = {}
        # What each search covered: an empty result proves only that this query, in
        # this scope and window, found nothing.
        self.searches: list[dict[str, Any]] = []

    @property
    def size(self) -> int:
        """Units of knowledge so far: objects, expanded entities and AD objects."""
        expanded = sum("relation_ids" in entry for entry in self.entities.values())
        return len(self.entities) + len(self.relations) + expanded + len(self.ad_objects)

    def observe(self, payload: Any, *, ad_context: bool = False) -> int:
        """Record entities and relations found in a compacted payload.

        Args:
            payload: Compacted alert or tool result.
            ad_context: The payload came from an Active Directory lookup.

        Returns:
            How much new knowledge it brought: new objects, newly expanded entities
            (relation ids learned) and new AD objects.
        """
        before = self.size
        self.last_entities = []
        if ad_context:
            for node in _walk(payload):
                if isinstance(node, dict) and isinstance(node.get("id"), str):
                    self.ad_objects.setdefault(node["id"], node)
            return self.size - before
        for node in _walk(payload):
            if not isinstance(node, dict) or not isinstance(node.get("id"), str):
                continue
            if "source_id" in node and "target_id" in node or "properties" in node:
                self.raw[node["id"]] = {**self.raw.get(node["id"], {}), **node}
            if "source_id" in node and "target_id" in node:
                entry = self.relations.setdefault(node["id"], {})
                entry.update(
                    {
                        key: node[key]
                        for key in ("type", "source_id", "target_id", "timestamp")
                        if key in node
                    }
                )
                # Logon type and source, granted access, call trace: relation facts are
                # evidence as much as entity fields are.
                if properties := relation_properties(node):
                    entry.setdefault("properties", {}).update(
                        {key: _shorten(item) for key, item in properties.items()}
                    )
            elif "properties" in node or node.get("kind") == "entity":
                entry = self.entities.setdefault(node["id"], {})
                if "type" in node:
                    entry["type"] = node["type"]
                if isinstance(node.get("properties"), dict):
                    entry.setdefault("properties", {}).update(
                        {key: _shorten(item) for key, item in node["properties"].items()}
                    )
                if isinstance(node.get("relation_ids"), dict):
                    entry["relation_ids"] = node["relation_ids"]
                entry["signals"] = entity_signals(entry.get("type"), entry.get("properties", {}))
                self.last_entities.append(node["id"])
        return self.size - before

    def record_search(self, arguments: dict[str, Any], result: Any) -> None:
        """Note what a search covered and what it returned."""
        if "query" not in arguments:
            return
        results = result.get("results") if isinstance(result, dict) else None
        found = Counter(
            str(node.get("type", "?"))
            for node in results or []
            if isinstance(node, dict) and node.get("kind", "entity") == "entity"
        )
        scope = arguments.get("scope")
        scope = scope if isinstance(scope, dict) else {}
        window = arguments.get("time_window")
        window = window if isinstance(window, dict) else {}
        self.searches.append(
            {
                "query": str(arguments["query"]),
                "type": scope.get("type"),
                "window": (window.get("from"), window.get("to")) if window else None,
                "found": dict(found),
                "more": bool(isinstance(result, dict) and result.get("next_page_id")),
                "page": arguments.get("page_id"),
            }
        )

    def coverage(self, limit: int = MAX_COVERAGE) -> list[str]:
        """What the searches covered, one line each, latest last.

        A search that found nothing in a narrow scope or window, or one with pages left
        unread, does not show that something did not happen.
        """
        lines = []
        for search in self.searches[-limit:]:
            scope = f" [{search['type']}]" if search["type"] else ""
            window = f" {search['window'][0]}..{search['window'][1]}" if search["window"] else ""
            page = f" page {search['page']}" if search["page"] else ""
            if search["found"]:
                found = ", ".join(f"{count} {kind}" for kind, count in search["found"].items())
                more = "; more pages unread" if search["more"] else ""
                lines.append(f"- {search['query'][:80]!r}{scope}{window}{page}: {found}{more}")
            else:
                lines.append(f"- {search['query'][:80]!r}{scope}{window}{page}: nothing found")
        return lines

    def signals(self, entity_ids: list[str]) -> dict[str, list[str]]:
        """Return non-empty analyst signals for the given entities."""
        return {
            entity_id: self.entities[entity_id]["signals"]
            for entity_id in dict.fromkeys(entity_ids)
            if self.entities.get(entity_id, {}).get("signals")
        }

    def cached(self, arguments: dict[str, Any]) -> dict[str, Any] | None:
        """Return a lookup's answer if the case file already holds the full object.

        Args:
            arguments: Tool arguments; only single entity or relation lookups qualify.

        Returns:
            The stored object, or None when the runtime has to be asked.
        """
        keys = set(arguments) - {"reasoning"}
        if keys == {"relation_id"}:
            node = self.raw.get(arguments["relation_id"])
            return node if node and "source_id" in node else None
        if keys == {"entity_id"}:
            node = self.raw.get(arguments["entity_id"])
            return node if node and "relation_ids" in node else None
        return None

    def relation_overview(self, entity_id: str) -> dict[str, Any]:
        """Split an entity's relation ids into already known relations and unfetched ids."""
        relation_ids = self.entities.get(entity_id, {}).get("relation_ids") or {}
        known: dict[str, str] = {}
        unfetched = 0
        for direction in ("incoming", "outgoing"):
            for relation_id in relation_ids.get(direction, []):
                relation = self.relations.get(relation_id)
                if relation:
                    known[relation_id] = (
                        f"{relation.get('type')} {relation.get('source_id')} -> "
                        f"{relation.get('target_id')}"
                    )
                else:
                    unfetched += 1
        return {"known": known, "unfetched": unfetched}

    def open_leads(self, limit: int = 5) -> list[str]:
        """Unexplored directions, suspicious ones first.

        Returns:
            Short hints naming an entity id and why it is worth a call.
        """
        suspicious = {
            entity_id
            for entity_id, entry in self.entities.items()
            if any(signal.startswith("suspicious") for signal in entry.get("signals", []))
        }
        leads: list[tuple[int, str]] = []
        for entity_id in suspicious:
            entry = self.entities[entity_id]
            if "relation_ids" not in entry:
                leads.append(
                    (
                        0,
                        f"{entity_id} [{entry.get('type')}] has suspicious signals and "
                        "its relations are unexplored",
                    )
                )
            elif (unfetched := self.relation_overview(entity_id)["unfetched"]) > 0:
                leads.append(
                    (1, f"{entity_id} [{entry.get('type')}] has {unfetched} unfetched relations")
                )
        for relation in self.relations.values():
            for end, other in (("source_id", "target_id"), ("target_id", "source_id")):
                endpoint = relation.get(end)
                if endpoint and endpoint not in self.entities:
                    rank = 2 if relation.get(other) in suspicious else 3
                    leads.append(
                        (
                            rank,
                            f"{endpoint} is the unseen {end.split('_')[0]} of "
                            f"{relation.get('type')} ({relation.get(other)})",
                        )
                    )
        leads.sort()
        return list(dict.fromkeys(text for _, text in leads))[:limit]

    def case_signals(self) -> list[str]:
        """Signals that only show across many entities, such as C2 beaconing."""
        endpoints: Counter[str] = Counter()
        for entry in self.entities.values():
            if entry.get("type") != "network_connection":
                continue
            properties = entry.get("properties", {})
            address = properties.get("dst_ip")
            if isinstance(address, str) and is_external(address):
                endpoints[str(properties.get("fqdn") or address)] += 1
        signals = [
            f"suspicious: {count} connections to external endpoint {endpoint} (possible beaconing)"
            for endpoint, count in endpoints.most_common()
            if count >= BEACON_MIN_CONNECTIONS
        ]
        return signals + self._lookalike_accounts()

    def _lookalike_accounts(self) -> list[str]:
        """Accounts whose names imitate another account seen in the case."""
        names: dict[str, str] = {}
        for entity_id, entry in self.entities.items():
            if entry.get("type") in {"windows_user", "linux_user"}:
                username = str((entry.get("properties") or {}).get("username") or "")
                if username:
                    names.setdefault(username, entity_id)
        found = []
        listed = sorted(names)
        for index, first in enumerate(listed):
            for second in listed[index + 1 :]:
                if lookalike(first, second) or lookalike(second, first):
                    found.append(
                        f"suspicious: accounts {first!r} ({names[first]}) and {second!r} "
                        f"({names[second]}) have lookalike names (possible impersonation)"
                    )
        return found[:MAX_LOOKALIKES]

    def strong_signals(self) -> list[str]:
        """Suspicious signals a benign verdict has to explain, with their entity ids."""
        found = [
            f"{entity_id}: {signal}"
            for entity_id, entry in self.entities.items()
            for signal in entry.get("signals", [])
            if any(marker in signal for marker in STRONG_SIGNAL_MARKERS)
        ]
        detections = [
            f"{entity_id}: matches detection {detection}"
            for entity_id, entry in self.entities.items()
            for detection in entry.get("detections", [])
            if "[TTP]" in detection
        ]
        return [*self.case_signals(), *found, *detections]

    def render(self, max_chars: int | None = None) -> str:
        """Render the case file as compact text for the LLM.

        Args:
            max_chars: Size budget; entity lines are shortened evenly to fit it.

        Returns:
            One line per entity and per relation.
        """
        entity_lines = []
        for entity_id, entry in self.entities.items():
            properties = render_inline(entry.get("properties", {}))
            line = f"- {entity_id} [{entry.get('type', '?')}] {properties}"
            if signals := entry.get("signals"):
                line += f" signals={render_inline(signals)}"
            if relation_ids := entry.get("relation_ids"):
                line += f" relation_ids={render_inline(relation_ids)}"
            entity_lines.append(line)
        relation_chars = 200 * len(self.relations)
        if max_chars is not None and entity_lines:
            per_line = max(160, (max_chars - relation_chars) // len(entity_lines))
            entity_lines = [
                line if len(line) <= per_line else f"{line[:per_line]}...[cut]"
                for line in entity_lines
            ]
        lines = [*self.case_signals(), f"Entities ({len(self.entities)}):", *entity_lines]
        lines.append(f"Relations ({len(self.relations)}):")
        for relation_id, entry in self.relations.items():
            timestamp = f" @ {entry['timestamp']}" if "timestamp" in entry else ""
            facts = entry.get("properties")
            lines.append(
                f"- {relation_id} [{entry.get('type', '?')}] {entry.get('source_id')} -> "
                f"{entry.get('target_id')}{timestamp}"
                + (f" {render_inline(facts)}" if facts else "")
            )
        if coverage := self.coverage():
            lines.append(f"Searches made ({len(self.searches)}, what each covered):")
            lines.extend(coverage)
        return "\n".join(lines)


def _without_marker(value: Any) -> Any:
    """`log_sources` without the benchmark's ground-truth marker."""
    if isinstance(value, list):
        return [item for item in value if item != GROUND_TRUTH_MARKER]
    return None if value == GROUND_TRUTH_MARKER else value


RELATION_KEYS = {"id", "kind", "type", "source_id", "target_id", "timestamp", "log_sources"}


def relation_properties(node: dict[str, Any]) -> dict[str, Any]:
    """A relation's own facts, from `properties` and typed blocks like `logon_properties`."""
    found: dict[str, Any] = {}
    for key, value in node.items():
        if key in RELATION_KEYS:
            continue
        if isinstance(value, dict) and (key == "properties" or key.endswith("_properties")):
            found.update({name: item for name, item in value.items() if item not in EMPTY_VALUES})
        elif value not in EMPTY_VALUES and not isinstance(value, (dict, list)):
            found[key] = value
    return found


def render_inline(value: Any) -> str:
    """Serialize a value on one line without extra whitespace."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def _shorten(value: Any) -> Any:
    """Cap long property values such as script bodies."""
    if isinstance(value, str) and len(value) > MAX_VALUE_CHARS:
        return f"{value[:MAX_VALUE_CHARS]}...[{len(value) - MAX_VALUE_CHARS} more chars]"
    return value


def _walk(node: Any) -> Any:
    """Yield every nested value in a JSON document."""
    yield node
    if isinstance(node, dict):
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk(value)
