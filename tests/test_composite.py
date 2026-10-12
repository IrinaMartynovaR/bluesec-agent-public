import asyncio
import json
from typing import Any, cast

from test_agent import CATALOG, REASONING, FakeActionClient, FakeClient, FakeSession

from bluesec1_agent.agent import InvestigationAgent
from bluesec1_agent.casefile import CaseFile
from bluesec1_agent.composite import creation_links, summarize_prevalence
from bluesec1_agent.models import AgentAction
from bluesec1_client import RemoteBenchmarkClient, ToolCallResult

SEARCH = {
    "name": "search",
    "description": "Search.",
    "parameters": {
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            "scope": {"type": "object"},
            "reasoning": REASONING,
        },
        "required": ["query", "reasoning"],
    },
}
PROCESSES = {
    "child": {"image_path": "C:\\Windows\\System32\\powershell.exe", "cmdline": "ps -enc A"},
    "parent": {"image_path": "C:\\Program Files\\Office\\WINWORD.EXE", "cmdline": "winword"},
    "root": {"image_path": "C:\\Windows\\explorer.exe", "cmdline": "explorer"},
}
EDGES = [("root", "parent"), ("parent", "child"), ("child", "grandchild")]


def create(source: str, target: str) -> dict[str, Any]:
    return {
        "kind": "relation",
        "id": f"{source}->{target}",
        "type": "win_process_create",
        "source_id": source,
        "target_id": target,
    }


def test_creation_links_split_parent_and_children() -> None:
    """The relation pointing at the process names its parent, the others its children."""
    result = {"results": [create("parent", "child"), create("child", "grandchild")]}

    assert creation_links(result, "child") == ("parent", ["grandchild"])


def test_prevalence_counts_hosts_accounts_and_binaries() -> None:
    """One search is summarized by where the value occurs."""
    case = CaseFile()
    case.observe({"id": "h1", "type": "host", "properties": {"hostname": "WS1"}})
    result = {
        "results": [
            {"id": "p1", "type": "windows_process", "host_id": "h1", "properties": {"user": "a"}},
            {"id": "p2", "type": "windows_process", "host_id": "h2", "properties": {"user": "a"}},
        ]
    }

    summary = summarize_prevalence("abcdef", result, case)

    assert summary["distinct_hosts"] == 2 and summary["hosts"] == {"WS1": 1, "h2": 1}
    assert summary["distinct_accounts"] == 1


class TreeSession(FakeSession):
    """Fake runtime holding a three-level process chain."""

    def __init__(self) -> None:
        """Advertise a search tool next to the base catalog."""
        super().__init__()
        self.task.observation["available_tools"] = json.dumps([*CATALOG, SEARCH])
        self.task.observation["alert_text"] = json.dumps(
            {"alert_description": "powershell", "trigger_entities": [{"id": "child"}]}
        )

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> ToolCallResult:
        """Answer entity lookups and process-creation searches from the chain."""
        if tool_name == "finish_investigation":
            return await super().call_tool(tool_name, arguments)
        self.calls.append((tool_name, arguments))
        if tool_name == "get_entity":
            entity_id = arguments["entity_id"]
            result: Any = {
                "id": entity_id,
                "type": "windows_process",
                "properties": PROCESSES[entity_id],
            }
        else:
            query = arguments["query"]
            result = {"results": [create(s, t) for s, t in EDGES if query in (s, t)]}
        return ToolCallResult(
            task_id="task-1",
            tool_name=tool_name,
            observation={},
            reward=0.0,
            terminated=False,
            info={"tool_status": "ok", "tool_result": result},
        )


def test_process_tree_walks_to_the_root_with_counted_calls() -> None:
    """One model turn opens the whole ancestry; every runtime call is spent and recorded."""
    tree = AgentAction(
        tool="process_tree", arguments={"entity_id": "child", "reasoning": "who started it"}
    )
    finish = AgentAction(
        tool="finish_investigation",
        arguments={
            "submission": {
                "verdict": "malicious",
                "ir_artifacts": [{"entity_id": "child", "kind": "process_observed"}],
            }
        },
    )
    llm = FakeActionClient([tree, finish])
    session = TreeSession()
    agent = InvestigationAgent(llm, review_finish=False, thinking="off", assess_samples=1)

    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))

    runtime = [name for name, _ in session.calls]
    assert runtime == [
        "get_entity",
        "search",
        "get_entity",
        "search",
        "get_entity",
        "search",
        "finish_investigation",
    ]
    answer = llm.requests[1][-1]["content"]
    assert answer.index("explorer.exe") < answer.index("WINWORD.EXE") < answer.index("[ASKED]")
    assert "grandchild" in answer
    assert '"runtime_calls":6' in answer.replace(" ", "")


def test_process_tree_records_each_inner_reward(tmp_path: Any) -> None:
    """Trace review sees every runtime call a composite tool spent, with its reward."""
    tree = AgentAction(
        tool="process_tree", arguments={"entity_id": "child", "reasoning": "who started it"}
    )
    finish = AgentAction(
        tool="finish_investigation",
        arguments={
            "submission": {
                "verdict": "malicious",
                "ir_artifacts": [{"entity_id": "child", "kind": "process_observed"}],
            }
        },
    )
    agent = InvestigationAgent(
        FakeActionClient([tree, finish]),
        review_finish=False,
        thinking="off",
        assess_samples=1,
        trajectory_dir=tmp_path,
    )

    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(TreeSession()))))

    saved = json.loads((tmp_path / "run-1" / "task-1.json").read_text())
    step = next(s for s in saved["steps"] if s["tool"] == "process_tree")
    assert step["inner_rewards"] == [0.0] * 6
    assert "inner_rewards" not in json.dumps(step.get("feedback", {}))
