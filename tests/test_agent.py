import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

from bluesec1_agent.agent import SYSTEM_PROMPT, InvestigationAgent
from bluesec1_agent.knowledge import KnowledgeBase
from bluesec1_agent.models import AgentAction, ToolCatalog
from bluesec1_client import (
    PublicTask,
    RemoteBenchmarkClient,
    RemoteBenchmarkSession,
    TaskResult,
    ToolCallResult,
)

REASONING = {"type": "string", "minLength": 1}
CATALOG = [
    {
        "name": "get_entity",
        "description": "Get one entity.",
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "properties": {"entity_id": {"type": "string"}, "reasoning": REASONING},
            "required": ["entity_id", "reasoning"],
        },
    },
    {
        "name": "finish_investigation",
        "description": "Finish.",
        "parameters": {
            "type": "object",
            "additionalProperties": False,
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


def get_entity(entity_id: str) -> AgentAction:
    """Build a graph navigation action."""
    return AgentAction(
        tool="get_entity",
        arguments={"entity_id": entity_id, "reasoning": f"Inspect {entity_id}."},
    )


FINISH = AgentAction(
    tool="finish_investigation",
    arguments={
        "submission": {
            "verdict": "benign",
            "legitimacy_evidence": [
                {"anchor": "entity", "entity_id": "entity-1", "property_fields": ["pid"]}
            ],
        }
    },
)


BENIGN_ASSESSMENT: dict[str, Any] = {
    "stages": [],
    "target_event": "none",
    "proximity": 0,
    "signal_explanations": [],
}


class FakeActionClient:
    """Deterministic actions used by the agent unit tests."""

    def __init__(self, actions: list[AgentAction]) -> None:
        """Store actions in their expected request order."""
        self.actions = list(actions)
        self.requests: list[list[dict[str, Any]]] = []
        self.forced: list[str | None] = []
        self.thinking: list[bool] = []

    async def next_action(
        self,
        messages: list[dict[str, Any]],
        catalog: ToolCatalog,
        *,
        force_tool: str | None = None,
        thinking: bool = False,
    ) -> AgentAction:
        """Record the conversation and return the next prepared action."""
        self.requests.append([dict(message) for message in messages])
        self.forced.append(force_tool)
        self.thinking.append(thinking)
        if force_tool == "assess_chain":
            return AgentAction(tool="assess_chain", arguments=BENIGN_ASSESSMENT)
        if force_tool is not None:
            return FINISH
        return self.actions.pop(0)


class FakeSession:
    """In-memory remote session."""

    def __init__(self) -> None:
        """Create a task with a JSON-encoded remote tool catalog."""
        self.task = PublicTask(
            task_id="task-1",
            observation={
                "alert_text": json.dumps(
                    {
                        "alert_description": "powershell on host-1",
                        "trigger_entities": [
                            {"id": f"entity-{index}", "properties": {"pid": index}}
                            for index in range(20)
                        ],
                    }
                ),
                "available_tools": json.dumps(CATALOG),
                "last_tool_result": "",
            },
        )
        self.calls: list[tuple[str, dict[str, Any]]] = []

    @property
    def task_id(self) -> str:
        """Return the public task identifier."""
        return self.task.task_id

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> ToolCallResult:
        """Record one call and terminate on the finishing tool."""
        self.calls.append((tool_name, arguments))
        terminal = tool_name == "finish_investigation"
        return ToolCallResult(
            task_id="task-1",
            tool_name=tool_name,
            observation={
                "available_tools": json.dumps(CATALOG),
                "last_tool_result": '{"entity_id": "process-1", "pid": 42}',
            },
            reward=1.0,
            terminated=terminal,
            info={"tool_status": "ok"},
            task_result=(
                TaskResult(task_id="task-1", completion_reason="terminated", quality_score=0.5)
                if terminal
                else None
            ),
        )

    async def abort_task(self, *, error_message: str | None = None) -> TaskResult:
        """Reject unexpected aborts."""
        raise AssertionError(f"Unexpected abort: {error_message}")


class FakeClient:
    """Single-task stand-in for an open RemoteBenchmarkClient."""

    def __init__(self, session: FakeSession) -> None:
        """Store the only session returned before queue exhaustion."""
        self.run = SimpleNamespace(run_id="run-1")
        self.session: FakeSession | None = session

    async def start_task(self) -> RemoteBenchmarkSession | None:
        """Lease the prepared session once."""
        if self.session is None:
            return None
        session, self.session = self.session, None
        return cast(RemoteBenchmarkSession, session)


def run_agent(llm: FakeActionClient, session: FakeSession, **kwargs: Any) -> Any:
    """Run the agent over one fake task, without the report review unless asked."""
    kwargs.setdefault("review_finish", False)
    kwargs.setdefault("thinking", "off")
    kwargs.setdefault("assess_samples", 1)
    kwargs.setdefault("report_samples", 1)
    kwargs.setdefault("report_form", False)
    kwargs.setdefault("pace", "normal")
    agent = InvestigationAgent(llm, **kwargs)
    return asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))


def test_agent_feeds_tool_results_without_the_catalog(tmp_path: Path) -> None:
    """Evidence reaches the next turn, the catalog never enters the context."""
    llm = FakeActionClient([get_entity("entity-1"), FINISH])
    session = FakeSession()

    result = run_agent(llm, session, trajectory_dir=tmp_path)

    assert result.successful_tasks == 1
    assert [name for name, _ in session.calls] == ["get_entity", "finish_investigation"]
    first_request, second_request = llm.requests
    assert first_request[0]["content"] == SYSTEM_PROMPT
    assert "powershell on host-1" in first_request[1]["content"]
    assert all("available_tools" not in str(message) for message in second_request)
    assert "process-1" in second_request[-1]["content"]
    saved = json.loads((tmp_path / "run-1" / "task-1.json").read_text())
    assert [step["tool"] for step in saved["steps"]] == ["get_entity", "finish_investigation"]
    assert saved["task_result"]["quality_score"] == 0.5


def test_agent_skips_duplicate_calls_locally() -> None:
    """A repeated call is answered locally and never costs a runtime call."""
    llm = FakeActionClient([get_entity("entity-1"), get_entity("entity-1"), FINISH])
    session = FakeSession()

    run_agent(llm, session, trajectory_dir=None)

    assert [name for name, _ in session.calls] == ["get_entity", "finish_investigation"]
    assert "Identical call" in llm.requests[2][-1]["content"]


def test_agent_forces_finish_on_last_call() -> None:
    """The final allowed call must be the finishing tool."""
    llm = FakeActionClient([get_entity("entity-1"), get_entity("entity-2")])
    session = FakeSession()

    run_agent(llm, session, max_steps=2, trajectory_dir=None)

    assert llm.forced == [None, "finish_investigation"]
    assert [name for name, _ in session.calls] == ["get_entity", "finish_investigation"]


def test_agent_warns_after_soft_budget() -> None:
    """Past the soft budget every tool result tells the model to wrap up."""
    llm = FakeActionClient([get_entity("entity-1"), FINISH])
    session = FakeSession()

    run_agent(llm, session, soft_steps=1, trajectory_dir=None)

    assert "budget_warning" in llm.requests[1][-1]["content"]


def test_agent_forces_finish_when_calls_stop_finding_anything() -> None:
    """Calls that surface nothing new end in a forced finish instead of a loop."""
    llm = FakeActionClient([get_entity(f"entity-{index}") for index in range(20)])
    session = FakeSession()

    run_agent(llm, session, trajectory_dir=None)

    assert llm.forced.count("finish_investigation") == 1
    assert len(session.calls) == 11
    assert "progress_warning" in llm.requests[-1][-1]["content"]


def test_agent_compacts_history_into_case_file() -> None:
    """Past the context limit old results are replaced by the case file."""
    llm = FakeActionClient([get_entity(f"entity-{index}") for index in range(8)] + [FINISH])
    session = FakeSession()

    run_agent(llm, session, context_max_chars=5_000, tool_result_max_chars=500, trajectory_dir=None)

    history = llm.requests[-1]
    assert "Case file" in history[1]["content"]
    assert any("moved to the case file" in str(message["content"]) for message in history)


def test_agent_forces_finish_on_stall_past_soft_budget() -> None:
    """Past the soft budget a short stall is enough to force the finish."""
    llm = FakeActionClient([get_entity(f"entity-{index}") for index in range(20)])
    session = FakeSession()

    run_agent(llm, session, soft_steps=2, trajectory_dir=None)

    assert len(session.calls) == 6


def test_agent_assesses_chain_before_the_report() -> None:
    """The first finishing call triggers a chain assessment and a rewritten report."""
    llm = FakeActionClient([get_entity("entity-1"), FINISH])
    session = FakeSession()

    run_agent(llm, session, review_finish=True, trajectory_dir=None)

    assert llm.forced == [None, None, "assess_chain", "finish_investigation"]
    assert llm.thinking == [False, False, True, True]
    assert "Call finish_investigation with a benign report" in llm.requests[-1][-1]["content"]
    assert [name for name, _ in session.calls] == ["get_entity", "finish_investigation"]


def test_knowledge_search_is_answered_locally_and_limited() -> None:
    """Knowledge searches never reach the runtime and stop at the per-task limit."""
    search = AgentAction(tool="knowledge_search", arguments={"query": "shadow copy"})
    other = AgentAction(tool="knowledge_search", arguments={"query": "vssadmin"})
    llm = FakeActionClient([search, other, FINISH])
    session = FakeSession()
    knowledge = KnowledgeBase(
        {"detections": [{"name": "Shadow copy deletion", "type": "TTP"}], "stories": []}
    )

    run_agent(llm, session, knowledge=knowledge, knowledge_calls=1, trajectory_dir=None)

    assert [name for name, _ in session.calls] == ["finish_investigation"]
    assert "Shadow copy deletion" in llm.requests[1][-1]["content"]
    assert "limit reached" in llm.requests[2][-1]["content"]


def test_longer_query_after_empty_search_is_skipped() -> None:
    """A query containing an earlier empty query cannot match and is not sent."""
    catalog = [
        *CATALOG,
        {
            "name": "search",
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string"}, "reasoning": REASONING},
                "required": ["query", "reasoning"],
            },
        },
    ]
    session = FakeSession()
    session.task = PublicTask(
        task_id="task-1",
        observation={**session.task.observation, "available_tools": json.dumps(catalog)},
    )

    async def empty_search(tool_name: str, arguments: dict[str, Any]) -> ToolCallResult:
        session.calls.append((tool_name, arguments))
        terminal = tool_name == "finish_investigation"
        return ToolCallResult(
            task_id="task-1",
            tool_name=tool_name,
            info={"tool_status": "ok", "tool_result": {"results": []}},
            terminated=terminal,
            task_result=TaskResult(task_id="task-1", completion_reason="terminated")
            if terminal
            else None,
        )

    session.call_tool = empty_search  # type: ignore[method-assign]
    search = AgentAction(tool="search", arguments={"query": "memory", "reasoning": "r"})
    longer = AgentAction(tool="search", arguments={"query": "memory-1.dmp", "reasoning": "r"})
    llm = FakeActionClient([search, longer, FINISH])

    run_agent(llm, session, trajectory_dir=None)

    assert [name for name, _ in session.calls] == ["search", "finish_investigation"]
    assert "already returned nothing" in llm.requests[2][-1]["content"]


def test_repeated_lookup_is_answered_from_the_case_file() -> None:
    """A repeat of a lookup whose data is stored comes back with the data, for free."""
    llm = FakeActionClient([get_entity("entity-1"), get_entity("entity-1"), FINISH])
    session = FakeSession()

    async def entity_lookup(tool_name: str, arguments: dict[str, Any]) -> ToolCallResult:
        session.calls.append((tool_name, arguments))
        terminal = tool_name == "finish_investigation"
        entity = {
            "id": "entity-1",
            "properties": {"pid": 1, "image_path": "C:\\x.exe"},
            "relation_ids": {"incoming": ["relation-1"]},
        }
        return ToolCallResult(
            task_id="task-1",
            tool_name=tool_name,
            info={"tool_status": "ok", "tool_result": entity},
            terminated=terminal,
            task_result=TaskResult(task_id="task-1", completion_reason="terminated")
            if terminal
            else None,
        )

    session.call_tool = entity_lookup  # type: ignore[method-assign]
    run_agent(llm, session, trajectory_dir=None)

    assert [name for name, _ in session.calls] == ["get_entity", "finish_investigation"]
    assert "here is its result again" in llm.requests[2][-1]["content"]
    assert '"pid": 1' in llm.requests[2][-1]["content"]


def test_unusable_replies_do_not_abort_the_task() -> None:
    """When the model cannot produce a valid call, the task continues instead of aborting."""
    from bluesec1_agent.llm import NextStepRequestError

    class FlakyClient(FakeActionClient):
        async def next_action(self, messages, catalog, *, force_tool=None, thinking=False):  # type: ignore[no-untyped-def]
            if not self.requests:
                self.requests.append(list(messages))
                raise NextStepRequestError("query '5985' is too short")
            return await super().next_action(
                messages, catalog, force_tool=force_tool, thinking=thinking
            )

    llm = FlakyClient([FINISH])
    session = FakeSession()

    run_agent(llm, session, trajectory_dir=None)

    assert [name for name, _ in session.calls] == ["finish_investigation"]
    assert "could not be used" in llm.requests[-1][-1]["content"]


def test_key_thinking_reasons_on_the_first_step_and_when_stuck() -> None:
    """Key mode thinks on the first step and once calls stop finding anything."""
    llm = FakeActionClient([get_entity(f"entity-{index}") for index in range(4)] + [FINISH])
    session = FakeSession()

    run_agent(llm, session, thinking="key", trajectory_dir=None)

    # Fake results carry no graph objects: after two empty calls the third step thinks.
    assert llm.thinking[:4] == [True, False, True, False]


def test_lookup_with_wrong_or_mistyped_id_is_redirected() -> None:
    """A relation id sent to the entity lookup goes to the relation tool; typos are fixed."""
    from bluesec1_agent.agent import _redirect_lookup
    from bluesec1_agent.ids import IdRegistry

    relation = "33333333-3333-5333-8333-333333333333"
    entity = "22222222-2222-5222-8222-222222222222"
    catalog = ToolCatalog.from_observation(
        {
            "available_tools": json.dumps(
                [
                    *CATALOG,
                    {
                        "name": "get_relation",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "relation_id": {"type": "string"},
                                "reasoning": REASONING,
                            },
                            "required": ["relation_id", "reasoning"],
                        },
                    },
                ]
            )
        }
    )
    registry = IdRegistry()
    registry.observe({"id": entity, "properties": {}, "relation_ids": {"incoming": [relation]}})

    wrong_kind = AgentAction(tool="get_entity", arguments={"entity_id": relation, "reasoning": "r"})
    typo = AgentAction(
        tool="get_entity", arguments={"entity_id": entity[:-3] + "999", "reasoning": "r"}
    )

    redirected = _redirect_lookup(wrong_kind, registry, catalog)
    fixed = _redirect_lookup(typo, registry, catalog)

    assert redirected.tool == "get_relation"
    assert redirected.arguments == {"relation_id": relation, "reasoning": "r"}
    assert fixed.arguments["entity_id"] == entity


class SamplingClient(FakeActionClient):
    """Returns prepared assessments in order, then a benign report."""

    def __init__(self, actions: list[AgentAction], assessments: list[dict[str, Any]]) -> None:
        super().__init__(actions)
        self.assessments = list(assessments)

    async def next_action(self, messages, catalog, *, force_tool=None, thinking=False):  # type: ignore[no-untyped-def]
        if force_tool == "assess_chain":
            self.requests.append([dict(message) for message in messages])
            self.forced.append(force_tool)
            self.thinking.append(thinking)
            return AgentAction(tool="assess_chain", arguments=self.assessments.pop(0))
        return await super().next_action(
            messages, catalog, force_tool=force_tool, thinking=thinking
        )


def test_agreeing_assessments_skip_the_tie_break() -> None:
    llm = SamplingClient([get_entity("entity-1"), FINISH], [BENIGN_ASSESSMENT] * 3)
    session = FakeSession()

    run_agent(llm, session, review_finish=True, assess_samples=3, trajectory_dir=None)

    assert llm.forced.count("assess_chain") == 3
    assert not any("assessments of this case disagree" in str(r) for r in llm.requests)


def test_disagreeing_assessments_trigger_a_tie_break() -> None:
    stage = {"tactic": "execution", "evidence": "x", "entity_ids": ["entity-1"]}
    malicious = {**BENIGN_ASSESSMENT, "proximity": 1, "stages": [stage]}
    llm = SamplingClient(
        [get_entity("entity-1"), FINISH],
        [BENIGN_ASSESSMENT, malicious, BENIGN_ASSESSMENT, BENIGN_ASSESSMENT],
    )
    session = FakeSession()

    run_agent(llm, session, review_finish=True, assess_samples=3, trajectory_dir=None)

    assert llm.forced.count("assess_chain") == 4
    assert "assessments of this case disagree" in llm.requests[-2][-1]["content"]


def test_sufficiency_checkpoint_asks_to_finish_and_thinks() -> None:
    """After the configured number of calls the model is asked whether it can finish."""
    llm = FakeActionClient([get_entity(f"entity-{index}") for index in range(3)] + [FINISH])
    session = FakeSession()

    run_agent(llm, session, thinking="key", checkpoint_after=2, trajectory_dir=None)

    assert "Checkpoint." in llm.requests[2][-1]["content"]
    assert llm.thinking[2] is True


def test_final_report_is_written_several_times_and_submitted_once() -> None:
    """Report samples cost LLM calls only; the runtime sees one merged report."""
    llm = FakeActionClient([get_entity("entity-1"), FINISH])
    session = FakeSession()

    run_agent(llm, session, review_finish=True, report_samples=3, trajectory_dir=None)

    assert llm.forced.count("finish_investigation") == 3
    assert [name for name, _ in session.calls] == ["get_entity", "finish_investigation"]


def test_llm_outage_mid_task_is_waited_out() -> None:
    """A transient provider error retries the step instead of aborting the task."""
    import httpx
    from openai import APIConnectionError

    class FlakyClient(FakeActionClient):
        failed = False

        async def next_action(self, messages: Any, catalog: Any, **kwargs: Any) -> AgentAction:
            if not self.failed:
                self.failed = True
                raise APIConnectionError(request=httpx.Request("POST", "http://llm"))
            return await super().next_action(messages, catalog, **kwargs)

    llm = FlakyClient([get_entity("entity-1"), FINISH])
    session = FakeSession()

    result = run_agent(llm, session, trajectory_dir=None)

    assert result.successful_tasks == 1
    assert [name for name, _ in session.calls] == ["get_entity", "finish_investigation"]


def test_disagreement_asks_for_the_deciding_fact_either_way() -> None:
    """Draft and assessment disagreeing sends the investigation back, symmetrically."""
    from bluesec1_agent.agent import _disagreement_message

    attack = _disagreement_message("malicious", "benign", {"decision": {"accepted_stages": 0}})
    legit = _disagreement_message(
        "benign", "malicious", {"decision": {"unexplained_signals": ["encoded command"]}}
    )

    assert "what the suspicious step actually did next" in attack
    assert "encoded command" in legit and "came out malicious" in legit
