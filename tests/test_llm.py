import asyncio
import json
from types import SimpleNamespace
from typing import Any, cast

import pytest
from openai import AsyncOpenAI

from bluesec1_agent.llm import NextStepRequestError, OpenAIToolCallingClient
from bluesec1_agent.models import ToolCatalog

CATALOG = ToolCatalog.from_observation(
    {
        "available_tools": json.dumps(
            [
                {
                    "name": "get_entity",
                    "parameters": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "entity_id": {"type": "string"},
                            "reasoning": {"type": "string", "minLength": 1},
                        },
                        "required": ["entity_id", "reasoning"],
                    },
                },
                {
                    "name": "finish_investigation",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "submission": {
                                "type": "object",
                                "properties": {"verdict": {"enum": ["benign", "malicious"]}},
                                "required": ["verdict"],
                            }
                        },
                        "required": ["submission"],
                    },
                },
            ]
        )
    }
)


def reply(name: str | None = None, arguments: Any = None, content: str = "") -> Any:
    """Build a fake chat completion with an optional tool call."""
    tool_calls = None
    if name is not None:
        raw = arguments if isinstance(arguments, str) else json.dumps(arguments)
        tool_calls = [SimpleNamespace(function=SimpleNamespace(name=name, arguments=raw))]
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content, tool_calls=tool_calls))],
        usage=SimpleNamespace(total_tokens=17),
    )


class FakeOpenAI:
    """Queue-backed fake for the chat completion endpoint."""

    def __init__(self, replies: list[Any]) -> None:
        """Store replies and record requests."""
        self.replies = list(replies)
        self.requests: list[dict[str, Any]] = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    async def create(self, **kwargs: Any) -> Any:
        """Return the next queued reply."""
        self.requests.append(kwargs)
        return self.replies.pop(0)


def make_client(fake: FakeOpenAI, **kwargs: Any) -> OpenAIToolCallingClient:
    """Build a client over the fake transport."""
    options: dict[str, Any] = {
        "base_url": "https://llm.example/v1",
        "api_key": "secret",
        "model": "test-model",
        "timeout_seconds": 10.0,
        "max_completion_tokens": 1000,
        "max_retries": 3,
        "client": cast(AsyncOpenAI, fake),
    }
    options.update(kwargs)
    return OpenAIToolCallingClient(**options)


MESSAGES = [{"role": "system", "content": "Investigate."}]
VALID_ARGS = {"entity_id": "entity-1", "reasoning": "Inspect the trigger."}


def test_client_repairs_invalid_arguments_outside_history() -> None:
    """Schema violations are retried without touching the caller's messages."""
    fake = FakeOpenAI(
        [reply("get_entity", {"entity_id": "entity-1"}), reply("get_entity", VALID_ARGS)]
    )
    original = list(MESSAGES)

    action = asyncio.run(make_client(fake).next_action(MESSAGES, CATALOG))

    assert action.arguments == VALID_ARGS
    assert len(fake.requests) == 2
    assert "reasoning" in fake.requests[1]["messages"][-1]["content"]
    assert fake.requests[0]["tool_choice"] == "required"
    assert original == MESSAGES


def test_client_decodes_nested_json_strings() -> None:
    """An object argument sent as a JSON string is decoded when that makes it valid."""
    fake = FakeOpenAI([reply("finish_investigation", {"submission": '{"verdict": "benign"}'})])

    action = asyncio.run(make_client(fake).next_action(MESSAGES, CATALOG))

    assert action.arguments == {"submission": {"verdict": "benign"}}


def test_client_rejects_unknown_tools_and_gives_up() -> None:
    """Unadvertised tools never pass validation."""
    fake = FakeOpenAI(
        [
            reply("delete_everything", {}),
            reply(content="thinking..."),
            reply("delete_everything", {}),
        ]
    )

    with pytest.raises(NextStepRequestError, match="not advertised"):
        asyncio.run(make_client(fake).next_action(MESSAGES, CATALOG))


def test_client_stops_when_the_same_invalid_call_repeats() -> None:
    """Repair turns stop once the model repeats the identical invalid call."""
    fake = FakeOpenAI([reply("get_entity", {"entity_id": "x"})] * 5)

    with pytest.raises(NextStepRequestError, match="reasoning"):
        asyncio.run(make_client(fake, max_retries=5).next_action(MESSAGES, CATALOG))
    assert len(fake.requests) == 2


def test_structure_is_repaired_to_the_chosen_variant() -> None:
    """Keys the chosen oneOf variant forbids are dropped; a wrapped object is unwrapped."""
    variant = {
        "oneOf": [
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "verdict": {"const": "malicious"},
                    "ir_artifacts": {"type": "array"},
                },
                "required": ["verdict", "ir_artifacts"],
            },
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {"verdict": {"const": "benign"}, "evidence": {"type": "array"}},
                "required": ["verdict", "evidence"],
            },
        ]
    }
    catalog = ToolCatalog.from_observation(
        {
            "available_tools": json.dumps(
                [
                    {
                        "name": "finish",
                        "parameters": {
                            "type": "object",
                            "properties": {"submission": variant},
                            "required": ["submission"],
                        },
                    }
                ]
            )
        }
    )
    mixed = {"submission": {"verdict": "malicious", "ir_artifacts": [], "evidence": []}}
    wrapped = {"submission": [{"verdict": "benign", "evidence": []}]}

    assert catalog.validate("finish", mixed) == (
        {"submission": {"verdict": "malicious", "ir_artifacts": []}},
        None,
    )
    assert catalog.validate("finish", wrapped)[0] == {
        "submission": {"verdict": "benign", "evidence": []}
    }


def test_client_forwards_forced_tool_and_sampling_options() -> None:
    """Forced tool, temperature and extra_body reach the request only when set."""
    extra_body = {"chat_template_kwargs": {"enable_thinking": False}, "repetition_penalty": 1.05}
    fake = FakeOpenAI(
        [
            reply("get_entity", VALID_ARGS),
            reply("finish_investigation", {"submission": {"verdict": "malicious"}}),
        ]
    )

    asyncio.run(make_client(fake).next_action(MESSAGES, CATALOG))
    asyncio.run(
        make_client(fake, temperature=0.3, extra_body=extra_body).next_action(
            MESSAGES, CATALOG, force_tool="finish_investigation"
        )
    )

    default_request, tuned_request = fake.requests
    assert "temperature" not in default_request
    assert "extra_body" not in default_request
    assert tuned_request["temperature"] == 0.3
    assert tuned_request["extra_body"] == extra_body
    assert tuned_request["tool_choice"]["function"]["name"] == "finish_investigation"
    assert [tool["function"]["name"] for tool in tuned_request["tools"]] == CATALOG.names


SCOPE_SCHEMA = {
    "anyOf": [
        {
            "type": "object",
            "properties": {"kind": {"const": "relation"}, "type": {"type": "string"}},
            "required": ["kind", "type"],
        },
        {"type": "null"},
    ]
}


def search_catalog(required: list[str]) -> ToolCatalog:
    """Catalog with one search tool whose scope is a nullable union."""
    return ToolCatalog.from_observation(
        {
            "available_tools": json.dumps(
                [
                    {
                        "name": "search",
                        "parameters": {
                            "type": "object",
                            "properties": {"query": {"type": "string"}, "scope": SCOPE_SCHEMA},
                            "required": required,
                        },
                    }
                ]
            )
        }
    )


def test_invalid_optional_argument_is_dropped() -> None:
    arguments, error = search_catalog(["query"]).validate(
        "search", {"query": "x", "scope": {"kind": "relation"}}
    )

    assert error is None
    assert arguments == {"query": "x"}


def test_schema_error_names_the_missing_field_in_a_union() -> None:
    _, error = search_catalog(["query", "scope"]).validate(
        "search", {"query": "x", "scope": {"kind": "relation"}}
    )

    assert error is not None
    assert "'type' is a required property" in error
    assert "null" not in error


def test_decoded_string_argument_reports_its_real_problem() -> None:
    raw = '{"verdict": "maybe"}'
    _, error = CATALOG.validate("finish_investigation", {"submission": raw})

    assert error is not None
    assert "maybe" in error and "is not of type 'object'" not in error


def test_lenient_decoding_accepts_escaped_quotes_and_newlines() -> None:
    raw = '{"verdict": "benign", "note": "line one\nsigner \\\'Microsoft\\\'"}'
    arguments, error = CATALOG.validate("finish_investigation", {"submission": raw})

    assert error is None
    assert arguments["submission"]["verdict"] == "benign"


def test_transient_provider_errors_are_retried() -> None:
    """A dropped connection is retried instead of failing the step."""
    import httpx
    from openai import APIConnectionError

    fake = FakeOpenAI([reply("get_entity", VALID_ARGS)])
    original_create = fake.chat.completions.create
    failures = [APIConnectionError(request=httpx.Request("POST", "https://llm.example/v1"))]

    async def flaky_create(**kwargs: Any) -> Any:
        if failures:
            raise failures.pop()
        return await original_create(**kwargs)

    fake.chat.completions.create = flaky_create
    client = make_client(fake, outage_wait_seconds=30.0)

    async def no_sleep(_: float) -> None:
        return None

    import bluesec1_agent.llm as llm_module

    original_sleep = llm_module.asyncio.sleep
    llm_module.asyncio.sleep = no_sleep  # type: ignore[assignment]
    try:
        action = asyncio.run(client.next_action(MESSAGES, CATALOG))
    finally:
        llm_module.asyncio.sleep = original_sleep  # type: ignore[assignment]

    assert action.tool == "get_entity"
