import asyncio
import json
from typing import Any, cast

from test_agent import CATALOG, REASONING, FakeActionClient, FakeClient, FakeSession

from bluesec1_agent.agent import InvestigationAgent
from bluesec1_agent.casefile import CaseFile
from bluesec1_agent.models import AgentAction
from bluesec1_agent.sweep import render_sweep, split_window, sweep_arguments
from bluesec1_client import RemoteBenchmarkClient, ToolCallResult

ALERT: dict[str, Any] = {
    "alert_description": "chrome on DESK12",
    "trigger_entities": [
        {
            "id": "host-1",
            "type": "host",
            "properties": {"hostname": "DESK12", "platform": "windows"},
        },
        {
            "id": "proc-1",
            "type": "windows_process",
            "properties": {
                "image_path": "C:\\Program Files\\Google\\Chrome\\chrome.exe",
                "user_sid": "S-1-5-21-1-2-3-1001",
                "logon_id": "0x356ec",
            },
            "host_id": "host-1",
            "timestamps": ["2024-06-12T09:21:51+00:00", "2024-06-12T10:00:00+00:00"],
        },
    ],
}
SEARCH = {
    "name": "search",
    "description": "Search.",
    "parameters": {
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            "scope": {"type": "object"},
            "time_window": {"type": "object"},
            "page_id": {"type": "integer"},
            "reasoning": REASONING,
        },
        "required": ["query", "reasoning"],
    },
}
WORD_CHILD = {
    "kind": "entity",
    "id": "proc-2",
    "type": "windows_process",
    "properties": {
        "image_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "parent_image": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
        "cmdline": "powershell -nop -w hidden -enc AAAA",
        "user": "CORP\\alice",
        "start_time": "2024-06-12T09:40:00+00:00",
    },
    "host_id": "host-1",
}

USER = {
    "kind": "entity",
    "id": "user-1",
    "type": "windows_user",
    "properties": {"sid": "S-1-5-21-1-2-3-1001", "username": "alice"},
}


def test_sweep_arguments_cover_the_alert_activity() -> None:
    """The window spans the trigger's activity plus margins, on the alert host."""
    arguments = sweep_arguments(ALERT)

    assert arguments is not None
    assert arguments["query"] == "host-1"
    assert arguments["scope"] == {"kind": "entity", "type": "windows_process"}
    assert arguments["time_window"] == {
        "from": "2024-06-12T08:21:51+00:00",
        "to": "2024-06-12T11:00:00+00:00",
    }


def test_split_window_puts_the_trigger_start_first() -> None:
    """The later part of the window is asked first, the hour before second."""
    arguments = sweep_arguments(ALERT)
    assert arguments is not None

    (first, after), (second, before) = split_window(arguments)

    assert first == "from the trigger's start on" and second == "in the hour before"
    assert after["time_window"] == {
        "from": "2024-06-12T09:16:51+00:00",
        "to": "2024-06-12T11:00:00+00:00",
    }
    assert before["time_window"]["from"] == "2024-06-12T08:21:51+00:00"
    assert before["time_window"]["to"] == after["time_window"]["from"]


def test_sweep_arguments_need_a_host_and_a_time() -> None:
    """Without a host entity or timestamps there is nothing to sweep."""
    assert sweep_arguments({"trigger_entities": ALERT["trigger_entities"][1:]}) is None
    no_time = [ALERT["trigger_entities"][0], {"id": "proc-1", "type": "windows_process"}]
    assert sweep_arguments({"trigger_entities": no_time}) is None


def test_render_sweep_marks_the_trigger_and_lists_facts() -> None:
    """Each process gets one line with its command, parent and computed signals."""
    case_file = CaseFile()
    results = [{**ALERT["trigger_entities"][1], "kind": "entity"}, WORD_CHILD]
    case_file.observe({"results": results})

    lines = render_sweep(results, case_file, {"proc-1"})

    assert len(lines) == 2
    assert "[ALERT]" in lines[0]
    assert "WINWORD.EXE" in lines[1] and "-enc AAAA" in lines[1]


class SweepSession(FakeSession):
    """Fake session whose alert names a host and whose catalog has a search tool."""

    def __init__(self) -> None:
        """Replace the alert and catalog of the base fake."""
        super().__init__()
        self.task.observation["alert_text"] = json.dumps(ALERT)
        self.task.observation["available_tools"] = json.dumps([*CATALOG, SEARCH])

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> ToolCallResult:
        """Answer the sweeps: one Word child, one remote logon, one other host."""
        if tool_name != "search":
            return await super().call_tool(tool_name, arguments)
        self.calls.append((tool_name, arguments))
        scope_type = arguments["scope"]["type"]
        results: list[dict[str, Any]] = [WORD_CHILD]
        if scope_type == "windows_user":
            results = [USER]
        elif scope_type == "logged_on_to":
            target = "host-1" if arguments["query"] == "host-1" else "host-2"
            results = [
                {
                    "kind": "relation",
                    "id": f"logon-{target}",
                    "type": "logged_on_to",
                    "source_id": "user-1",
                    "target_id": target,
                    "timestamp": "2024-06-12T09:00:00+00:00",
                    "logon_properties": {"logon_type": "network", "source_ip": "10.0.0.5"},
                }
            ]
        return ToolCallResult(
            task_id="task-1",
            tool_name=tool_name,
            observation={},
            reward=0.0,
            terminated=False,
            info={"tool_status": "ok", "tool_result": {"results": results}},
        )


def test_agent_shows_the_host_timeline_before_the_first_turn() -> None:
    """The sweep runs once, costs a runtime call and reaches the first prompt."""
    finish = AgentAction(
        tool="finish_investigation",
        arguments={
            "submission": {
                "verdict": "benign",
                "legitimacy_evidence": [
                    {"anchor": "entity", "entity_id": "proc-1", "property_fields": ["image_path"]}
                ],
            }
        },
    )
    llm = FakeActionClient([finish])
    session = SweepSession()
    agent = InvestigationAgent(
        llm,
        review_finish=False,
        thinking="off",
        assess_samples=1,
        host_sweep_pages=2,
        logon_sweep=True,
        account_context=False,
        sweep_split=True,
    )

    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))

    searches = [arguments for name, arguments in session.calls if name == "search"]
    assert [arguments["scope"]["type"] for arguments in searches] == [
        "windows_process",
        "windows_process",
        "logged_on_to",
        "windows_user",
        "logged_on_to",
    ]
    assert [searches[0]["query"], searches[1]["query"]] == ["0x356ec", "0x356ec"]
    assert searches[0]["time_window"]["from"] == "2024-06-12T09:16:51+00:00"
    assert searches[1]["time_window"]["to"] == "2024-06-12T09:16:51+00:00"
    assert searches[3]["query"] == "S-1-5-21-1-2-3-1001"
    assert searches[4]["query"] == "user-1"
    first_prompt = llm.requests[0][1]["content"]
    assert "logon session 0x356ec" in first_prompt
    assert "from the trigger's start on" in first_prompt
    assert "Host timeline" not in first_prompt  # both pages went to the session
    assert "proc-2" in first_prompt and "-enc AAAA" in first_prompt
    assert "Logons to the alert host" in first_prompt and "from=10.0.0.5" in first_prompt
    assert "Other hosts the alert's account" in first_prompt and "host-2" in first_prompt


AD_TOOL = {
    "name": "get_ad_object_info",
    "description": "AD object.",
    "parameters": {
        "type": "object",
        "properties": {"ad_object_id": {"type": "string"}, "reasoning": REASONING},
        "required": ["ad_object_id", "reasoning"],
    },
}


class AccountSession(SweepSession):
    """Fake runtime with a directory tool and an account that has a directory object."""

    def __init__(self) -> None:
        """Advertise the directory tool too."""
        super().__init__()
        self.task.observation["available_tools"] = json.dumps([*CATALOG, SEARCH, AD_TOOL])

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> ToolCallResult:
        """Answer the account search with a linked user and the directory lookup."""
        if tool_name == "get_ad_object_info":
            self.calls.append((tool_name, arguments))
            result = {"id": "ad-1", "description": "Service account for AD tiering -- CAB123"}
        elif tool_name == "search" and arguments["scope"]["type"] == "windows_user":
            self.calls.append((tool_name, arguments))
            result = {
                "results": [{**USER, "properties": {**USER["properties"], "ad_object_id": "ad-1"}}]
            }
        else:
            return await super().call_tool(tool_name, arguments)
        return ToolCallResult(
            task_id="task-1",
            tool_name=tool_name,
            observation={},
            reward=0.0,
            terminated=False,
            info={"tool_status": "ok", "tool_result": result},
        )


def test_account_context_opens_the_directory_object() -> None:
    """The trigger account is found by SID and its AD description reaches the prompt."""
    finish = AgentAction(
        tool="finish_investigation",
        arguments={
            "submission": {
                "verdict": "benign",
                "legitimacy_evidence": [
                    {"anchor": "entity", "entity_id": "proc-1", "property_fields": ["image_path"]}
                ],
            }
        },
    )
    llm = FakeActionClient([finish])
    session = AccountSession()
    agent = InvestigationAgent(
        llm,
        review_finish=False,
        thinking="off",
        assess_samples=1,
        host_sweep_pages=0,
        account_context=True,
        account_directory=True,
    )

    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))

    assert [name for name, _ in session.calls] == [
        "search",
        "get_ad_object_info",
        "finish_investigation",
    ]
    assert session.calls[0][1]["query"] == "S-1-5-21-1-2-3-1001"
    prompt = llm.requests[0][1]["content"]
    assert "Account of the trigger (user-1)" in prompt and "CAB123" in prompt


def test_render_sweep_collapses_repeated_commands() -> None:
    """Repeats that differ only in numbers become one line; signals stay apart."""
    case_file = CaseFile()

    def process(entity_id: str, cmdline: str, path: str = "C:\\tools\\kubectl.exe") -> dict:
        return {
            "kind": "entity",
            "id": entity_id,
            "type": "windows_process",
            "properties": {"image_path": path, "cmdline": cmdline, "start_time": entity_id},
        }

    results = [
        process("k1", "kubectl get pods --since 10s"),
        process("k2", "kubectl get pods --since 20s"),
        process("k3", "kubectl get pods --since 30s"),
        process("x1", "evil.exe", "C:\\Users\\Public\\evil.exe"),
    ]
    case_file.observe({"results": results})

    lines = render_sweep(results, case_file, set())

    assert len(lines) == 2
    assert "x3 similar until k3" in lines[0]
    assert "evil.exe" in lines[1]


def test_account_context_skips_the_directory_by_default() -> None:
    """Only the account entity is opened unless the directory object is asked for."""
    finish = AgentAction(
        tool="finish_investigation",
        arguments={
            "submission": {
                "verdict": "benign",
                "legitimacy_evidence": [
                    {"anchor": "entity", "entity_id": "proc-1", "property_fields": ["image_path"]}
                ],
            }
        },
    )
    llm = FakeActionClient([finish])
    session = AccountSession()
    agent = InvestigationAgent(
        llm, review_finish=False, thinking="off", assess_samples=1, host_sweep_pages=0
    )

    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))

    assert [name for name, _ in session.calls] == ["search", "finish_investigation"]
    assert "Account of the trigger (user-1)" in llm.requests[0][1]["content"]
