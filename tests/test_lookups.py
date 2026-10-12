import json
from typing import Any

from test_agent import CATALOG, REASONING, FakeActionClient, FakeSession, run_agent

from bluesec1_agent.models import AgentAction
from bluesec1_client import ToolCallResult


def tool(name: str, argument: str) -> dict[str, Any]:
    return {
        "name": name,
        "description": name,
        "parameters": {
            "type": "object",
            "properties": {argument: {"type": "string"}, "reasoning": REASONING},
            "required": [argument, "reasoning"],
        },
    }


class LookupSession(FakeSession):
    """Fake runtime with directory, relation and search tools."""

    def __init__(self) -> None:
        super().__init__()
        self.task.observation["available_tools"] = json.dumps(
            [
                *CATALOG,
                tool("get_ad_object_info", "ad_object_id"),
                tool("get_relation", "relation_id"),
                tool("search", "query"),
            ]
        )
        self.task.observation["alert_text"] = json.dumps(
            {
                "alert_description": "x",
                "trigger_entities": [
                    {"id": "u1", "type": "windows_user", "properties": {"ad_object_id": "ad-1"}},
                    {"id": "u2", "type": "windows_user", "properties": {"ad_object_id": "ad-2"}},
                ],
            }
        )

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> ToolCallResult:
        if tool_name == "finish_investigation":
            return await super().call_tool(tool_name, arguments)
        self.calls.append((tool_name, arguments))
        result: Any = {"results": []}
        if tool_name == "get_entity":
            result = {
                "id": arguments["entity_id"],
                "type": "windows_process",
                "properties": {"pid": 1},
                "relation_ids": {"incoming": ["rel-9"], "outgoing": []},
            }
        return ToolCallResult(
            task_id="task-1",
            tool_name=tool_name,
            observation={},
            reward=0.0,
            terminated=False,
            info={"tool_status": "ok", "tool_result": result},
        )


def act(name: str, **arguments: str) -> AgentAction:
    return AgentAction(tool=name, arguments={**arguments, "reasoning": "check"})


FINISH = AgentAction(
    tool="finish_investigation",
    arguments={
        "submission": {
            "verdict": "benign",
            "legitimacy_evidence": [{"anchor": "entity", "entity_id": "u1", "property_fields": []}],
        }
    },
)


def test_directory_lookups_stop_at_the_task_limit() -> None:
    """The second directory lookup is answered locally with a pointer to the user entity."""
    llm = FakeActionClient(
        [
            act("get_ad_object_info", ad_object_id="ad-1"),
            act("get_ad_object_info", ad_object_id="ad-2"),
            FINISH,
        ]
    )
    session = LookupSession()

    run_agent(llm, session, trajectory_dir=None)

    assert [name for name, _ in session.calls] == ["get_ad_object_info", "finish_investigation"]
    assert "limited per task" in llm.requests[2][-1]["content"]


def test_unseen_relation_is_opened_by_searching_its_owner() -> None:
    """A lookup of a relation known only by id becomes one search of its owner entity."""
    llm = FakeActionClient(
        [act("get_entity", entity_id="u1"), act("get_relation", relation_id="rel-9"), FINISH]
    )
    session = LookupSession()

    run_agent(llm, session, trajectory_dir=None)

    assert [name for name, _ in session.calls] == ["get_entity", "search", "finish_investigation"]
    assert session.calls[1][1]["query"] == "u1"
