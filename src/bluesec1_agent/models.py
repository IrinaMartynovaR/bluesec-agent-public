import copy
import json
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import best_match
from loguru import logger
from pydantic import BaseModel, ConfigDict, Field

FINISH_TOOL = "finish_investigation"


class StrictModel(BaseModel):
    """Base model that rejects fields outside the public structured contract."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class ToolSpec(BaseModel):
    """One tool advertised by the runtime in `available_tools`."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    name: str = Field(min_length=1)
    description: str = ""
    parameters: dict[str, Any] = Field(default_factory=lambda: {"type": "object"})
    function_schema: dict[str, Any] | None = None

    def openai_tool(self) -> dict[str, Any]:
        """Return the OpenAI `tools` entry for this tool.

        Returns:
            The runtime-provided function schema, or one built from `parameters`.
        """
        if self.function_schema is not None:
            return self.function_schema
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


class AgentAction(StrictModel):
    """One validated tool call chosen by the LLM."""

    thought: str = ""
    reasoning: str = ""
    tool: str
    arguments: dict[str, Any]


class ToolCatalog:
    """Runtime tool catalog with local argument validation."""

    def __init__(self, specs: list[ToolSpec]) -> None:
        """Index tool specifications by name.

        Args:
            specs: Advertised tool specifications.

        Raises:
            ValueError: If the catalog is empty or has duplicate names.
        """
        if not specs:
            raise ValueError("available_tools advertises no tools.")
        self.specs = {spec.name: spec for spec in specs}
        if len(self.specs) != len(specs):
            raise ValueError("available_tools advertises duplicate tool names.")
        self._validators = {spec.name: Draft202012Validator(spec.parameters) for spec in specs}

    @classmethod
    def from_observation(cls, observation: dict[str, Any]) -> "ToolCatalog":
        """Decode the runtime tool catalog from a task observation.

        Args:
            observation: Current public task observation.

        Returns:
            Parsed catalog.

        Raises:
            ValueError: If `available_tools` is absent or malformed.
        """
        raw_tool_specs = observation.get("available_tools")
        if isinstance(raw_tool_specs, str):
            try:
                raw_tool_specs = json.loads(raw_tool_specs)
            except json.JSONDecodeError as exc:
                raise ValueError("available_tools is not valid JSON.") from exc
        if not isinstance(raw_tool_specs, list) or not all(
            isinstance(specification, dict) for specification in raw_tool_specs
        ):
            raise ValueError("available_tools must encode a list of tool specifications.")
        return cls([ToolSpec.model_validate(specification) for specification in raw_tool_specs])

    @property
    def names(self) -> list[str]:
        """Return advertised tool names in catalog order."""
        return list(self.specs)

    def with_tools(self, extra: list[dict[str, Any]]) -> "ToolCatalog":
        """Return a catalog extended with local tools the runtime does not know."""
        return ToolCatalog(
            [*self.specs.values(), *(ToolSpec.model_validate(item) for item in extra)]
        )

    def openai_tools(self) -> list[dict[str, Any]]:
        """Return the catalog as an OpenAI `tools` request field."""
        return [spec.openai_tool() for spec in self.specs.values()]

    def validate(self, tool: str, arguments: Any) -> tuple[dict[str, Any], str | None]:
        """Validate arguments locally so malformed calls never reach the runtime.

        Models sometimes encode a nested object argument as a JSON string; such
        values are decoded when that is what makes the arguments valid.

        Args:
            tool: Tool name chosen by the model.
            arguments: Decoded tool arguments.

        Returns:
            Possibly normalized arguments and an error message, or None when valid.
        """
        if tool not in self.specs:
            return {}, f"Tool {tool!r} is not advertised. Available tools: {self.names}."
        if not isinstance(arguments, dict):
            return {}, "Tool arguments must be a JSON object."
        error = self._schema_error(tool, arguments)
        if error is None:
            return arguments, None
        decoded = _decode_embedded_json(arguments)
        if decoded != arguments:
            # Report what is wrong with the decoded form: "this is a string" hides the
            # real problem from the model.
            arguments, error = decoded, self._schema_error(tool, decoded)
            if error is None:
                return arguments, None
        repaired = self._repair_structure(tool, arguments)
        if repaired is not None:
            logger.info("Repaired the structure of {} arguments to fit its schema.", tool)
            return repaired, None
        trimmed = self._drop_invalid_optional(tool, arguments)
        if trimmed is not None:
            logger.info(
                "Dropped invalid optional arguments {} of {}.",
                sorted(set(arguments) - set(trimmed)),
                tool,
            )
            return trimmed, None
        return arguments, error

    def _repair_structure(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any] | None:
        """Apply one structural fix the schema itself dictates, if that makes the call valid.

        Only shape is changed, never content: keys the schema forbids at that place
        are removed, and a one-element list is unwrapped where the schema expects an
        object. Each candidate fix is tried alone, so for a oneOf only the fix of the
        variant the model chose (e.g. by its verdict) can succeed.

        Args:
            tool: Tool name.
            arguments: Arguments that fail validation.

        Returns:
            Valid repaired arguments, or None.
        """
        errors = list(self._validators[tool].iter_errors(arguments))
        leaves = [leaf for error in errors for leaf in _leaf_errors(error)]
        for leaf in leaves:
            candidate = copy.deepcopy(arguments)
            target = _resolve(candidate, list(leaf.absolute_path))
            if target is None:
                continue
            container, key, value = target
            if leaf.validator == "additionalProperties" and isinstance(value, dict):
                allowed = set((leaf.schema or {}).get("properties", {}))
                fixed = {k: v for k, v in value.items() if k in allowed}
            elif (
                leaf.validator == "type"
                and leaf.validator_value == "object"
                and isinstance(value, list)
                and len(value) == 1
                and isinstance(value[0], dict)
            ):
                fixed = value[0]
            else:
                continue
            if container is None:
                candidate = fixed
            else:
                container[key] = fixed
            if isinstance(candidate, dict) and self._schema_error(tool, candidate) is None:
                return candidate
        return None

    def _drop_invalid_optional(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any] | None:
        """Remove top-level optional arguments that fail the schema, if that fixes the call.

        Args:
            tool: Tool name.
            arguments: Arguments that fail validation.

        Returns:
            Valid arguments without the offending optional keys, or None.
        """
        required = set(self.specs[tool].parameters.get("required", []))
        offending = {
            str(error.absolute_path[0])
            for error in self._validators[tool].iter_errors(arguments)
            if error.absolute_path
        }
        if not offending or offending & required:
            return None
        trimmed = {key: value for key, value in arguments.items() if key not in offending}
        return trimmed if self._schema_error(tool, trimmed) is None else None

    def _schema_error(self, tool: str, arguments: dict[str, Any]) -> str | None:
        """Return the most relevant schema violation, if any."""
        errors = list(self._validators[tool].iter_errors(arguments))
        if not errors:
            return None
        error = min(errors, key=lambda item: len(item.absolute_path))
        details = [_describe(error)]
        if error.context:
            # oneOf/anyOf: best_match alone names one branch, which misleads the
            # model when it picked the other variant. Show the concrete leaf causes of
            # every branch, missing required fields first, and skip the null branch.
            leaves = [
                leaf
                for leaf in _leaf_errors(error)
                if not (leaf.validator == "type" and leaf.validator_value == "null")
            ]
            leaves.sort(key=lambda leaf: leaf.validator != "required")
            details = list(dict.fromkeys(_describe(leaf) for leaf in leaves[:6])) or details
        elif best := best_match(errors):
            details = [_describe(best)]
        return f"Invalid arguments for {tool}: " + "; ".join(details)[:1_500]


def _leaf_errors(error: Any) -> list[Any]:
    """Innermost schema errors under a oneOf/anyOf failure."""
    if not error.context:
        return [error]
    return [leaf for sub_error in error.context for leaf in _leaf_errors(sub_error)]


def _resolve(document: Any, path: list[Any]) -> tuple[Any, Any, Any] | None:
    """Return (parent container, key, value) for a JSON path; parent is None at the root."""
    if not path:
        return None, None, document
    parent = document
    for step in path[:-1]:
        try:
            parent = parent[step]
        except (KeyError, IndexError, TypeError):
            return None
    try:
        return parent, path[-1], parent[path[-1]]
    except (KeyError, IndexError, TypeError):
        return None


def _describe(error: Any) -> str:
    """Render one schema violation with its argument path and the parameter's own rules."""
    location = "/".join(str(part) for part in error.absolute_path) or "<root>"
    text = f"at {location}: {error.message}"
    if error.validator in {"minLength", "maxLength", "minimum", "maximum", "minItems"}:
        text += f" ({error.validator} {error.validator_value})"
    schema = error.schema if isinstance(error.schema, dict) else {}
    if description := schema.get("description"):
        text += f"; parameter: {description}"
    return text


def _decode_embedded_json(value: Any) -> Any:
    """Recursively decode strings that hold a JSON object or array."""
    if isinstance(value, dict):
        return {key: _decode_embedded_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_decode_embedded_json(item) for item in value]
    if isinstance(value, str) and value.strip()[:1] in {"{", "["}:
        decoded = _loads_lenient(value)
        if isinstance(decoded, (dict, list)):
            return _decode_embedded_json(decoded)
    return value


def _loads_lenient(text: str) -> Any:
    """Parse JSON a model wrote inside a string, tolerating raw newlines and \\' escapes."""
    for candidate in (text, text.replace("\\'", "'")):
        try:
            return json.loads(candidate, strict=False)
        except json.JSONDecodeError:
            continue
    return None
