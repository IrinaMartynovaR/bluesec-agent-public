import difflib
import json
import re
from collections.abc import Collection, Iterator
from typing import Any, Literal

Role = Literal["entity", "relation", "ad_object"]

UUID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
ARGUMENT_ROLES: dict[str, Role] = {
    "entity_id": "entity",
    "relation_id": "relation",
    "ad_object_id": "ad_object",
}
AD_REFERENCE_KEYS = ("ad_object_id", "member_of_ids", "manager_id", "_by_ids", "allowed_to")
ROLE_ARGUMENTS: dict[Role, str] = {role: key for key, role in ARGUMENT_ROLES.items()}
# Models mis-copy long ids; a near-identical known id is taken as the intended one.
ID_MATCH_CUTOFF = 0.85
ID_PREFIX = 13


class IdRegistry:
    """Remember which ids the agent has seen and what kind of object each names.

    The runtime charges for every call, including ones rejected with
    "Unknown entity_id". Knowing roles lets the agent reject a relation id passed
    as an entity id, or an id the model made up, before it reaches the runtime.
    """

    def __init__(self) -> None:
        """Start with no known ids."""
        self.roles: dict[str, set[Role]] = {}
        self.seen: set[str] = set()

    def observe(self, payload: Any, *, ad_context: bool = False) -> None:
        """Record every id in an alert or tool result.

        Args:
            payload: Decoded JSON, or a string holding JSON.
            ad_context: The payload came from an Active Directory lookup.
        """
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                return
        for node in _walk(payload):
            if isinstance(node, str) and UUID_PATTERN.match(node):
                self.seen.add(node)
            elif isinstance(node, dict):
                self._classify(node, ad_context)
                # Values of id fields count whatever their format, so the check below
                # does not depend on ids being UUIDs.
                for key, value in node.items():
                    if key == "id" or key.endswith(("_id", "_ids")):
                        for item in value if isinstance(value, list) else [value]:
                            if isinstance(item, str) and item:
                                self.seen.add(item)

    def check(self, arguments: dict[str, Any]) -> str | None:
        """Explain why an id argument is certainly wrong, or return None.

        Args:
            arguments: Validated tool arguments, possibly nested.

        Returns:
            A hint for the model, or None when every id is plausible.
        """
        for key, value in _id_arguments(arguments):
            expected = ARGUMENT_ROLES[key]
            if self.seen and value not in self.seen:
                close = difflib.get_close_matches(value, self.seen, n=1, cutoff=0.8)
                hint = f" Did you mean {close[0]!r}?" if close else ""
                return (
                    f"{key} {value!r} never appeared in the alert or any tool result; "
                    f"copy ids exactly.{hint}"
                )
            known = self.roles.get(value, set())
            # AD objects are also graph entities of type ad_object, so an AD id may
            # legitimately stand where an entity id is expected (e.g. an identity).
            if expected == "entity" and known == {"ad_object"}:
                continue
            if known and expected not in known:
                actual = " or ".join(sorted(known))
                return (
                    f"{value!r} is a {actual} id, not an {expected} id. "
                    f"Pass it to the tool that takes a {actual.replace('_', ' ')} id instead."
                )
        return None

    def sole_role(self, value: str) -> Role | None:
        """The only role an id is known to have, or None when unknown or ambiguous."""
        roles = self.roles.get(value, set())
        return next(iter(roles)) if len(roles) == 1 else None

    def _classify(self, node: dict[str, Any], ad_context: bool) -> None:
        """Assign roles to the ids one JSON object defines or references."""
        node_id = node.get("id")
        if isinstance(node_id, str):
            if ad_context:
                self._add(node_id, "ad_object")
            elif node.get("kind") == "relation" or {"source_id", "target_id"} <= node.keys():
                self._add(node_id, "relation")
            elif node.get("kind") == "entity" or "properties" in node:
                self._add(node_id, "entity")
        for key in ("source_id", "target_id", "host_id"):
            if isinstance(node.get(key), str):
                self._add(node[key], "entity")
        relation_ids = node.get("relation_ids")
        if isinstance(relation_ids, dict):
            for ids in relation_ids.values():
                for relation_id in ids if isinstance(ids, list) else []:
                    self._add(relation_id, "relation")
        for key, value in node.items():
            if any(marker in key for marker in AD_REFERENCE_KEYS):
                for ad_id in value if isinstance(value, list) else [value]:
                    if isinstance(ad_id, str):
                        self._add(ad_id, "ad_object")

    def _add(self, value: str, role: Role) -> None:
        """Record one id with one role."""
        self.seen.add(value)
        self.roles.setdefault(value, set()).add(role)


def resolve_id(value: str, known: Collection[str]) -> str | None:
    """Return the known id the model meant, or None.

    Exact ids pass through. A mis-copied id resolves when exactly one known id shares
    its prefix, or when one known id is nearly identical to it.
    """
    if value in known:
        return value
    if len(value) >= ID_PREFIX:
        prefixed = [candidate for candidate in known if candidate[:ID_PREFIX] == value[:ID_PREFIX]]
        if len(prefixed) == 1:
            return prefixed[0]
    close = difflib.get_close_matches(value, list(known), n=1, cutoff=ID_MATCH_CUTOFF)
    return close[0] if close else None


def _walk(node: Any) -> Iterator[Any]:
    """Yield every nested value in a JSON document."""
    yield node
    if isinstance(node, dict):
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk(value)


def _id_arguments(node: Any) -> Iterator[tuple[str, str]]:
    """Yield (argument name, value) for every id-typed argument, however nested."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ARGUMENT_ROLES and isinstance(value, str):
                yield key, value
            else:
                yield from _id_arguments(value)
    elif isinstance(node, list):
        for value in node:
            yield from _id_arguments(value)
