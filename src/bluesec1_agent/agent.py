import asyncio
from pathlib import Path
from typing import Any, cast

from loguru import logger
from pydantic import BaseModel, ConfigDict, Field

from bluesec1_agent.casefile import CaseFile, compact
from bluesec1_agent.composite import (
    COMPOSITE_TOOLS,
    PROCESS_CREATE,
    creation_links,
    render_tree,
    summarize_prevalence,
)
from bluesec1_agent.hypotheses import HYPOTHESES_TOOL, HypothesisBoard
from bluesec1_agent.ids import ARGUMENT_ROLES, ROLE_ARGUMENTS, IdRegistry, resolve_id
from bluesec1_agent.keepalive import PROBE_REASONING, KeepAliveSession
from bluesec1_agent.knowledge import SEARCH_TOOL, KnowledgeBase
from bluesec1_agent.linkage import linked_entities
from bluesec1_agent.llm import TRANSIENT_ERRORS, ActionClient, NextStepRequestError, render_json
from bluesec1_agent.models import FINISH_TOOL, AgentAction, ToolCatalog, ToolSpec
from bluesec1_agent.prompts import (
    ASSESS_PROMPT,
    ASSESS_TOOL,
    COVERAGE_NOTE,
    FINAL_PROMPT,
    RECONCILE_PROMPT,
    SYSTEM_PROMPT,
    TIE_BREAK_PROMPT,
)
from bluesec1_agent.report_check import (
    BENIGN_SHAPES,
    MAX_LEGITIMACY_EVIDENCE,
    check_submission,
    filter_artifacts,
    retarget_file_artifacts,
    shape_benign_report,
    vote_reports,
)
from bluesec1_agent.report_form import (
    FORM_PROMPT,
    LEGITIMACY_FORM_TOOL,
    MAX_FORM_ITEMS,
    build_benign_report,
)
from bluesec1_agent.stacking import (
    STACK_REASONING,
    key_processes,
    stable_fragment,
    summarize_stack,
)
from bluesec1_agent.sweep import (
    LOGON_REASONING,
    LOGON_SCOPE,
    account_query,
    alert_host,
    render_logons,
    render_sweep,
    session_query,
    split_window,
    sweep_arguments,
)
from bluesec1_agent.trajectory import TrajectoryRecorder
from bluesec1_agent.verdict import decide
from bluesec1_client import (
    RemoteBenchmarkClient,
    RemoteBenchmarkSession,
    TaskResult,
    ToolCallResult,
)

IGNORED_OBSERVATION_KEYS = {"available_tools", "last_tool_result"}
MAX_CONSECUTIVE_SKIPS = 3
# Calls in a row that surface no new entity or relation before the model is warned,
# and before it is made to finish.
STALE_WARN_CALLS = 5
STALE_FORCE_CALLS = 10
# A brisker pace: nudge, force and checkpoint sooner.
BRISK_STALE_WARN_CALLS = 3
BRISK_STALE_FORCE_CALLS = 6
BRISK_CHECKPOINT_AFTER = 10
# The lean pace also tells the model to finish past this many calls.
LEAN_SOFT_STEPS = 15
PACES = ("lean", "brisk", "normal")
# Calls without news after which the model is shown the open leads.
LEADS_AFTER_STALE_CALLS = 2
# Sufficiency checkpoints: after this many calls, then every CHECKPOINT_EVERY calls.
CHECKPOINT_EVERY = 5
MAX_CHECKPOINT_SIGNALS = 6
CHECKPOINT_PROMPT = (
    "Checkpoint. Do you already have: the entry point, the chain to the impact, every "
    "compromised host and account (or, if benign, the facts that explain each suspicious "
    "signal), and the strongest signal resolved? For an attack, have you checked where it "
    "spread from the compromised host - outbound connections to admin ports (SMB 445, RPC "
    "135, WinRM 5985/5986, RDP 3389, SSH 22) and logons of the accounts it used on other "
    "hosts? A missed compromised host or account costs more than any extra call. If all is "
    "answered, submit the final report now. If not, name the one missing piece and get it "
    "with the fewest calls. Do not search for stages you have no lead for."
)
# Provider outages a task waits out before it gives up.
MAX_LLM_RECOVERIES = 2
# Calls between planned reflection steps in "key" thinking mode.
REFLECT_EVERY_CALLS = 5
THINKING_MODES = ("off", "key", "all")
# Unfetched relations of one entity from which a single search beats one call each.
SEARCH_HINT_RELATIONS = 2
# Raw tool results kept verbatim when the history is compacted into the case file.
KEEP_RECENT_RESULTS = 6
COMPACTED_RESULT = "[result moved to the case file in the first message]"
# Local tool answered by the model only; it never reaches the runtime.
ASSESS_CATALOG = ToolCatalog([ToolSpec.model_validate(ASSESS_TOOL)])
FORM_CATALOG = ToolCatalog([ToolSpec.model_validate(LEGITIMACY_FORM_TOOL)])
FORM_NAME = LEGITIMACY_FORM_TOOL["name"]
VERDICTS = ("benign", "malicious")
AD_LIMIT_MESSAGE = (
    "Directory lookups are limited per task and this one is spent. The account's own "
    "entity (windows_user, found by searching its SID or name) holds its groups and "
    "privilege; use it, or go on with the investigation."
)
STACK_NOTE = (
    "How often the key commands of this case occur in this environment, counted before "
    "your assessment. Administrators and attackers run the same commands; routine work "
    "repeats (many runs, several hosts, one service or admin account, a schedule), an "
    "intrusion is rare (one host, one account, a shape seen nowhere else). Rarity alone "
    "does not prove an attack and frequency alone does not prove legitimacy - attackers "
    "also repeat themselves - but weigh it explicitly, together with who ran it and why."
)
LINKAGE_NOTE = (
    "Entities the investigation opened, ranked by how they are tied to the alert: a value "
    "the alert's command line shares with them, a direct relation, the same logon session, "
    "the same host. These are facts about links, not verdicts. Build the report from what "
    "was found: the strongly tied entities that prove your verdict are usually the ones to "
    "cite, and an entity tied to the alert only through its host rarely is."
)
RELATION_SEARCH_REASONING = (
    "List this entity's relations with their types and endpoints, the asked relation "
    "among them, instead of opening one relation."
)
MAX_LISTED_SIGNALS = 30
KNOWLEDGE_TOOL = SEARCH_TOOL["name"]
HYPOTHESES_NAME = HYPOTHESES_TOOL["name"]
# Free board updates allowed per task, so the model cannot loop on them.
HYPOTHESIS_UPDATES = 10
HYPOTHESIS_PROMPT = (
    "Before your first graph call, record the competing hypotheses with the hypotheses "
    "tool: at least one legitimate and one malicious explanation (mark each with its "
    "side), and one for any "
    "suspicious activity next to the alert in the tables above. Update them as evidence "
    "comes in; the report waits until each is supported or refuted."
)
# Entity types the knowledge base has detection conditions for.
MATCHABLE_TYPES = {"windows_process", "linux_process", "powershell_script", "registry_key"}
SWEEP_NOTE = (
    "Processes that ran around the alert time, opened by an automatic search before your "
    "first turn. The alert is not always where the attack is: attacker "
    "activity often runs next to it on the same host (an Office or browser child, an "
    "encoded or download command, a tool from a user-writable path, discovery commands). "
    "Most entries are ordinary background activity. Judge the entries with signals or "
    "detections, and anything the trigger's account ran, before judging the trigger."
)
LOGON_NOTE = (
    "A network or remote-interactive logon names the address it came from: in an attack, "
    "that host is part of the scope; in legitimate work, the account and source explain "
    "the session."
)
ACCOUNT_REASONING = (
    "Account context: who the trigger's account is and what it is for, so sanctioned "
    "administration and automation are told apart from abuse of the same commands."
)
ACCOUNT_NOTE = (
    "The account the trigger ran as, opened before your first turn. Its role, groups and "
    "directory description say what it is for; weigh them against what it did, in both "
    "directions: a sanctioned purpose explains matching activity, not activity outside it."
)
SPREAD_NOTE = (
    "If the alert is an attack, check whether these sessions belong to it (same time, "
    "same tools): a host the attacker reached is reported like the first one."
)


class AgentRunResult(BaseModel):
    """Aggregate results returned by one remote benchmark run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    successful_tasks: int
    failed_tasks: int
    task_results: list[TaskResult] = Field(default_factory=list)


class InvestigationAgent:
    """Run a native tool-calling investigation loop over the runtime tool catalog."""

    def __init__(
        self,
        llm: ActionClient,
        *,
        max_steps: int = 100,
        soft_steps: int | None = None,
        tool_result_max_chars: int = 20_000,
        context_max_chars: int = 120_000,
        review_finish: bool = True,
        knowledge: KnowledgeBase | None = None,
        knowledge_calls: int = 8,
        llm_recovery_wait_seconds: float = 720.0,
        thinking: str = "key",
        assess_samples: int = 3,
        report_samples: int = 3,
        composite_tools: bool = True,
        process_tree: bool = False,
        hypotheses: bool = True,
        report_form: bool = True,
        benign_shape: str = "core_people",
        pace: str = "lean",
        ad_lookups: int = 1,
        detections: bool = False,
        stacking: bool = True,
        checkpoint_after: int | None = 15,
        artifact_filter: bool = True,
        host_sweep_pages: int = 1,
        logon_sweep: bool = False,
        account_context: bool = True,
        account_directory: bool = False,
        sweep_split: bool = False,
        trajectory_dir: Path | None = None,
        run_metadata: dict[str, Any] | None = None,
    ) -> None:
        """Store the LLM dependency and per-task limits.

        Args:
            llm: Tool-call generator used for every investigation turn.
            max_steps: Maximum runtime tool calls allowed for one task.
            soft_steps: After this many calls the model is told to finish; None disables it.
            tool_result_max_chars: Longest tool result kept in the LLM context.
            context_max_chars: History size that triggers compaction into the case file.
            review_finish: Before the first report, assess the chain in thinking mode and let
                the code derive the verdict from that assessment.
            knowledge: Detection knowledge base offered to the model; None disables it.
            knowledge_calls: Knowledge searches allowed per task (they cost no score).
            llm_recovery_wait_seconds: After a task lost to an LLM outage, how long to
                wait for the provider before leasing the next task.
            thinking: Reasoning mode for investigation steps: "off", "key" (first
                step, after calls that found nothing, every few calls) or "all".
            assess_samples: Independent chain assessments per task; when their verdicts
                disagree a tie-break assessment weighs them against each other.
            report_samples: Independently written final reports; artifacts and facts most
                of them name are kept.
            composite_tools: Offer prevalence (and process_tree, if enabled), which
                assemble fleet prevalence and ancestry from ordinary runtime calls.
            process_tree: Also offer process_tree. Off: across three practice runs it
                spent about three calls a task and almost never reached new evidence.
            hypotheses: Have the model keep competing hypotheses on a board the code
                checks; a report with open hypotheses is held once.
            report_form: Write benign reports as a form of roles (what ran, who, what
                started it, what for) assembled by the code.
            benign_shape: What a benign report keeps (`shape_benign_report`):
                "core_people", "core" or "model" (as written).
            pace: "lean" nudges the model to finish after fewer fruitless calls, asks
                sooner whether the case is complete and tells it to finish past 15
                calls; "brisk" does the same without the call budget; "normal" keeps the
                slower thresholds.
            ad_lookups: Directory lookups allowed per task; they inform the verdict but
                never add report evidence.
            detections: Match every entity against the detection rules and offer the
                knowledge search. Off by default: in practice the matches fired as often
                in legitimate cases as in attacks and added strong signals to explain.
            stacking: Before the verdict, count how often each key command's shape
                occurs in the graph (up to three searches).
            checkpoint_after: Calls after which, and then every few calls, the model is asked
                in thinking mode whether the case is complete; None disables it.
            artifact_filter: Drop forensic artifacts the accepted attack chain does not
                support before the report is submitted.
            host_sweep_pages: Pages of the alert host's process timeline opened before the
                model's first turn; 0 disables the sweep.
            account_context: Before the first turn, open the trigger's account entity.
            account_directory: Also open the account's Active Directory object.
            sweep_split: Give the process sweep's first page to the part of the window
                from the trigger's start on, the second to the hour before.
            logon_sweep: Before the first turn, list logons to the alert host and the
                hosts the alert's account logged on to.
            trajectory_dir: Where to save per-task trajectories; None disables it.
            run_metadata: Settings recorded next to the trajectories.

        Raises:
            ValueError: If a configured limit is not positive.
        """
        if max_steps < 1:
            raise ValueError("max_steps must be positive")
        if tool_result_max_chars < 1:
            raise ValueError("tool_result_max_chars must be positive")
        self.llm = llm
        self.max_steps = max_steps
        self.soft_steps = soft_steps
        self.tool_result_max_chars = tool_result_max_chars
        self.context_max_chars = context_max_chars
        self.review_finish = review_finish
        self.knowledge = knowledge
        self.knowledge_calls = knowledge_calls
        self.llm_recovery_wait_seconds = llm_recovery_wait_seconds
        if thinking not in THINKING_MODES:
            raise ValueError(f"thinking must be one of {THINKING_MODES}")
        self.thinking = thinking
        if assess_samples < 1:
            raise ValueError("assess_samples must be positive")
        self.assess_samples = assess_samples
        if report_samples < 1:
            raise ValueError("report_samples must be positive")
        self.report_samples = report_samples
        self.composite_tools = composite_tools
        self.process_tree = process_tree
        self.hypotheses = hypotheses
        self.report_form = report_form
        if benign_shape not in BENIGN_SHAPES:
            raise ValueError(f"benign_shape must be one of {BENIGN_SHAPES}")
        self.benign_shape = benign_shape
        if pace not in PACES:
            raise ValueError(f"pace must be one of {PACES}")
        self.pace = pace
        self.ad_lookups = ad_lookups
        self.detections = detections
        self.stacking = stacking
        self.checkpoint_after = checkpoint_after
        self.artifact_filter = artifact_filter
        self.host_sweep_pages = host_sweep_pages
        self.logon_sweep = logon_sweep
        self.account_context = account_context
        self.account_directory = account_directory
        self.sweep_split = sweep_split
        self.trajectory_dir = trajectory_dir
        self.run_metadata = dict(run_metadata or {})

    async def run(
        self,
        client: RemoteBenchmarkClient,
        *,
        max_tasks: int | None = None,
    ) -> AgentRunResult:
        """Consume the remote queue and aggregate authoritative task results.

        Args:
            client: Open remote benchmark client that owns the current run.
            max_tasks: Stop after this many tasks; None consumes the whole queue.

        Returns:
            Aggregate result for the newly created remote run.

        Raises:
            RuntimeError: If the client is not open.
        """
        remote_run = client.run
        if remote_run is None:
            raise RuntimeError("RemoteBenchmarkClient must be open before running the agent.")
        recorder = TrajectoryRecorder(self.trajectory_dir, remote_run.run_id, self.run_metadata)

        task_results: list[TaskResult] = []
        while max_tasks is None or len(task_results) < max_tasks:
            session = await client.start_task()
            if session is None:
                break
            logger.info("Starting investigation for task {}.", session.task_id)
            record: dict[str, Any] = {"observation": _public_context(session.task.observation)}
            try:
                task_result = await self._investigate(session, record)
            except Exception as exc:
                logger.error("Task {} failed in the agent: {}", session.task_id, exc)
                error_message = f"{type(exc).__name__}: {exc}"[:2_000]
                record["agent_error"] = error_message
                aborted_result = await session.abort_task(error_message=error_message)
                task_result = TaskResult.model_validate(aborted_result)
                if isinstance(exc, TRANSIENT_ERRORS):
                    # Do not lease more tasks into an outage: each would be lost too.
                    await self._wait_for_llm()
            record["task_result"] = task_result.model_dump(mode="json")
            recorder.save_task(session.task_id, record)
            logger.info(
                "Task {} finished: reason={} quality={:.3f} efficiency={:.3f} "
                "reward={:.3f} tool_calls={}",
                session.task_id,
                task_result.completion_reason,
                task_result.quality_score,
                task_result.efficiency_score,
                task_result.total_reward,
                task_result.tool_calls,
            )
            task_results.append(task_result)

        successful_tasks = sum(
            result.completion_reason in {"terminated", "truncated"} for result in task_results
        )
        return AgentRunResult(
            run_id=remote_run.run_id,
            successful_tasks=successful_tasks,
            failed_tasks=len(task_results) - successful_tasks,
            task_results=task_results,
        )

    async def _investigate(
        self,
        session: RemoteBenchmarkSession,
        record: dict[str, Any],
    ) -> TaskResult:
        """Investigate one task while keeping its run open through long LLM phases."""
        catalog = ToolCatalog.from_observation(session.task.observation)
        alert = compact(_public_context(session.task.observation))
        body = alert.get("alert_text") if isinstance(alert, dict) else None
        trigger = next(
            (
                entity["id"]
                for entity in (body or {}).get("trigger_entities") or []
                if isinstance(entity, dict) and isinstance(entity.get("id"), str)
            ),
            None,
        )
        entity_tool = _runtime_tool(catalog, "entity_id")
        probe = (
            (entity_tool, {"entity_id": trigger, "reasoning": PROBE_REASONING})
            if entity_tool and trigger
            else None
        )
        guarded = KeepAliveSession(session, probe)
        keeper = asyncio.create_task(guarded.keep_alive())
        try:
            return await self._investigate_task(cast(RemoteBenchmarkSession, guarded), record)
        finally:
            keeper.cancel()
            if guarded.probes:
                record["keepalive_probes"] = guarded.probes
                logger.warning("Kept the run open with {} probe calls.", guarded.probes)

    async def _investigate_task(
        self,
        session: RemoteBenchmarkSession,
        record: dict[str, Any],
    ) -> TaskResult:
        """Drive one leased task until its terminal investigation tool succeeds.

        Args:
            session: Active remote task session.
            record: Mutable trajectory record filled with every step.

        Returns:
            Authoritative terminal task result returned by the server.

        Raises:
            ValueError: If the task observation has an invalid tool catalog.
            RuntimeError: If the agent exhausts its step budget.
        """
        catalog = ToolCatalog.from_observation(session.task.observation)
        if FINISH_TOOL not in catalog.specs:
            raise ValueError(f"The runtime did not advertise {FINISH_TOOL}.")
        logger.debug("Advertised tools: {}", catalog.names)

        alert = compact(record["observation"])
        task_prompt = "Investigate this alert and submit the final report.\n\n" + render_json(alert)
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": task_prompt},
        ]
        case_file = CaseFile()
        case_file.observe(alert)
        if alert_signals := case_file.signals(case_file.last_entities):
            task_prompt += "\n\nAnalyst signals computed from the alert: " + render_json(
                alert_signals
            )
        if alert_detections := self._match_detections(case_file):
            task_prompt += "\n\nKnowledge base detections matching the alert: " + render_json(
                alert_detections
            )
        attached_guides: set[str] = set()
        if alert_guides := self._new_guides(
            case_file, case_file.last_entities, attached_guides, is_trigger=True
        ):
            task_prompt += "\n\nPlaybook for this alert (follow it):\n" + "\n\n".join(
                alert_guides.values()
            )
        messages[1]["content"] = task_prompt
        local_tools = [SEARCH_TOOL] if self.knowledge and self.detections else []
        board = HypothesisBoard()
        hypothesis_updates = 0
        hypotheses_held = not self.hypotheses
        if self.hypotheses:
            local_tools.append(HYPOTHESES_TOOL)
        if (
            self.composite_tools
            and _runtime_tool(catalog, "query")
            and _runtime_tool(catalog, "entity_id")
        ):
            local_tools += [
                spec
                for name, spec in COMPOSITE_TOOLS.items()
                if name != "process_tree" or self.process_tree
            ]
        llm_catalog = catalog.with_tools(local_tools) if local_tools else catalog
        knowledge_searches = 0
        steps: list[dict[str, Any]] = []
        record["steps"] = steps
        registry = IdRegistry()
        registry.observe(record["observation"])
        for value in record["observation"].values():
            registry.observe(value)
        seen_calls: dict[str, int] = {}
        empty_searches: list[dict[str, Any]] = []
        tool_calls = 0
        if self.host_sweep_pages > 0 or self.logon_sweep or self.account_context:
            sweep_text, tool_calls = await self._sweep_host(
                session, catalog, alert, case_file, registry, steps, seen_calls
            )
            if sweep_text:
                record["pre_investigation"] = sweep_text
                task_prompt += "\n\n" + sweep_text
                messages[1]["content"] = task_prompt
        if self.hypotheses:
            task_prompt += "\n\n" + HYPOTHESIS_PROMPT
            messages[1]["content"] = task_prompt
        consecutive_skips = 0
        stale_calls = 0
        new_strong_signal = False
        checkpoint_due = False
        checkpoint_at: int | None = None
        strong_seen = len(case_file.strong_signals())
        reviewed = not self.review_finish
        llm_recoveries = 0
        ad_tool = _runtime_tool(catalog, "ad_object_id")
        ad_lookups = 0
        disagreement_held = False
        # Stacking runs once per task; a report sent back for a disputed fact reuses it.
        stacked = False
        stack_text = ""
        brisk = self.pace in ("lean", "brisk")
        soft_steps = (
            min(LEAN_SOFT_STEPS, self.soft_steps or LEAN_SOFT_STEPS)
            if self.pace == "lean"
            else self.soft_steps
        )
        stale_warn = BRISK_STALE_WARN_CALLS if brisk else STALE_WARN_CALLS
        stale_force = BRISK_STALE_FORCE_CALLS if brisk else STALE_FORCE_CALLS
        checkpoint_after = (
            min(BRISK_CHECKPOINT_AFTER, self.checkpoint_after or BRISK_CHECKPOINT_AFTER)
            if brisk
            else self.checkpoint_after
        )
        alert_body = alert.get("alert_text") if isinstance(alert, dict) else None
        trigger_ids = {
            str(entity["id"])
            for entity in (alert_body or {}).get("trigger_entities") or []
            if isinstance(entity, dict) and entity.get("id")
        }
        expected_verdict: str | None = None
        chain_entities: set[str] | None = None

        for turn in range(1, 2 * self.max_steps + 1):
            calls_left = self.max_steps - tool_calls - getattr(session, "probes", 0)
            if calls_left <= 0:
                break
            must_finish = (
                calls_left == 1
                or consecutive_skips >= MAX_CONSECUTIVE_SKIPS
                or stale_calls >= stale_force
                # Past the soft budget the model tends to ignore warnings, so a
                # shorter stall is enough to stop it.
                or (
                    soft_steps is not None
                    and tool_calls >= soft_steps
                    and stale_calls >= stale_warn
                )
            )
            think = self.thinking == "all" or (
                self.thinking == "key"
                and not must_finish
                and (
                    turn == 1
                    or stale_calls == LEADS_AFTER_STALE_CALLS
                    or new_strong_signal
                    or checkpoint_due
                    or (tool_calls > 0 and tool_calls % REFLECT_EVERY_CALLS == 0)
                )
            )
            new_strong_signal = False
            checkpoint_due = False
            try:
                action = await self.llm.next_action(
                    messages,
                    llm_catalog,
                    force_tool=FINISH_TOOL if must_finish else None,
                    thinking=think,
                )
            except TRANSIENT_ERRORS as exc:
                # A provider outage mid-task is waited out and the same step retried;
                # aborting would cost the whole task.
                if llm_recoveries >= MAX_LLM_RECOVERIES:
                    raise
                llm_recoveries += 1
                logger.warning("LLM unavailable mid-task ({}); waiting to retry the step.", exc)
                await self._wait_for_llm()
                continue
            except NextStepRequestError as exc:
                if must_finish:
                    raise
                # The model kept producing an unusable call: tell it and let it choose
                # another step instead of losing the whole task.
                consecutive_skips += 1
                messages.append(
                    {
                        "role": "user",
                        "content": f"Your last replies could not be used: {exc} "
                        "Choose a different call or finish the investigation.",
                    }
                )
                logger.warning("Unusable LLM replies, asking for another step: {}", exc)
                continue
            if (
                action.tool == FINISH_TOOL
                and not hypotheses_held
                and not must_finish
                and (open_labels := board.open())
            ):
                hypotheses_held = True
                call_id = f"call_{turn}"
                messages.append(_assistant_message(call_id, action))
                held = {
                    "status": "held",
                    "message": (
                        "These hypotheses are still open: "
                        + "; ".join(line for line in board.render() if "[open]" in line)
                        + ". Resolve each with the hypotheses tool - supported or refuted, "
                        "citing the entity ids that show it - or make the one call that "
                        "decides it. Then submit the report again."
                    ),
                }
                messages.append(
                    {"role": "tool", "content": render_json(held), "tool_call_id": call_id}
                )
                steps.append(
                    {
                        "turn": turn,
                        "tool": action.tool,
                        "arguments": action.arguments,
                        "status": "held",
                        "feedback": held,
                    }
                )
                logger.info("Held the report: {} hypotheses open.", len(open_labels))
                continue
            draft = None
            if action.tool == FINISH_TOOL and not reviewed:
                if self.stacking and not stacked and not must_finish:
                    stacked = True
                    stack_text, spent = await self._stack(
                        session, catalog, case_file, registry, trigger_ids, seen_calls, steps
                    )
                    tool_calls += spent
                    if stack_text:
                        record["stacking"] = stack_text
                reviewed = True
                draft = action
                action, assessment, expected_verdict = await self._review(
                    messages,
                    catalog,
                    action,
                    case_file,
                    attached_guides,
                    stacking=stack_text,
                    trigger_ids=trigger_ids,
                )
                draft_verdict = (draft.arguments.get("submission") or {}).get("verdict")
                if (
                    expected_verdict is not None
                    and draft_verdict in VERDICTS
                    and draft_verdict != expected_verdict
                    and not disagreement_held
                    and not must_finish
                ):
                    # The investigation and the assessment read the case differently:
                    # settle the disputed fact before either side wins.
                    disagreement_held = True
                    reviewed = False
                    call_id = f"call_{turn}"
                    messages.append(_assistant_message(call_id, draft))
                    held = {
                        "status": "held",
                        "message": _disagreement_message(
                            draft_verdict, expected_verdict, assessment
                        ),
                    }
                    messages.append(
                        {"role": "tool", "content": render_json(held), "tool_call_id": call_id}
                    )
                    steps.append(
                        {
                            "turn": turn,
                            "tool": draft.tool,
                            "arguments": draft.arguments,
                            "status": "held",
                            "feedback": held,
                            "assessment": assessment,
                            "derived_verdict": expected_verdict,
                        }
                    )
                    logger.info(
                        "Held the report: draft {} but assessment {}.",
                        draft_verdict,
                        expected_verdict,
                    )
                    continue
            if not must_finish:
                action = _redirect_lookup(action, registry, catalog)
                action = _relation_to_search(action, case_file, catalog, seen_calls)
            call_id = f"call_{turn}"
            messages.append(_assistant_message(call_id, action))
            step: dict[str, Any] = {
                "turn": turn,
                "tool": action.tool,
                "arguments": action.arguments,
                "thought": action.thought,
            }
            if action.reasoning:
                step["reasoning"] = action.reasoning
            if draft is not None:
                step["draft_arguments"] = draft.arguments
                step["assessment"] = assessment
                step["derived_verdict"] = expected_verdict
                decision_record = (assessment or {}).get("decision") or {}
                if "chain_entities" in decision_record:
                    chain_entities = set(decision_record["chain_entities"])
            if self.artifact_filter and action.tool == FINISH_TOOL and chain_entities is not None:
                filtered, dropped = filter_artifacts(
                    action.arguments,
                    chain_entities,
                    case_file,
                    trigger_ids,
                    benign_cap=MAX_FORM_ITEMS if self.report_form else MAX_LEGITIMACY_EVIDENCE,
                )
                if dropped:
                    action = action.model_copy(update={"arguments": filtered})
                    step["arguments"] = filtered
                    step["dropped_artifacts"] = dropped
                    messages[-1] = _assistant_message(call_id, action)
                    logger.info("Dropped {} artifacts outside the attack chain.", len(dropped))
            if action.tool == FINISH_TOOL and reviewed:
                shaped, added = shape_benign_report(
                    action.arguments, case_file, trigger_ids, self.benign_shape
                )
                if shaped is not action.arguments and _valid_finish(catalog, shaped):
                    action = action.model_copy(update={"arguments": shaped})
                    step["arguments"] = shaped
                    step["benign_shape_added"] = added
                    messages[-1] = _assistant_message(call_id, action)
            if action.tool == FINISH_TOOL:
                retargeted, process_ids = retarget_file_artifacts(action.arguments, case_file)
                if process_ids and _valid_finish(catalog, retargeted):
                    action = action.model_copy(update={"arguments": retargeted})
                    step["arguments"] = retargeted
                    step["retargeted_files"] = process_ids
                    messages[-1] = _assistant_message(call_id, action)
                    logger.info("Pointed {} file artifacts at their image files.", len(process_ids))
            steps.append(step)

            call_key = _call_key(action)
            id_problem = None if must_finish else registry.check(action.arguments)
            if id_problem is None and action.tool == FINISH_TOOL and not must_finish:
                id_problem = check_submission(action.arguments, case_file, expected_verdict)
            if action.tool != FINISH_TOOL and call_key in seen_calls:
                # A repeated lookup gets its data back from the case file for free; only
                # repeats that cannot be answered count toward the loop limit.
                repeated = case_file.cached(action.arguments)
                if repeated is None:
                    consecutive_skips += 1
                feedback: dict[str, Any] = {
                    "status": "ok" if repeated is not None else "skipped",
                    "message": (
                        f"Identical call already made at turn {seen_calls[call_key]}; "
                        + (
                            "here is its result again from the case file, no call spent."
                            if repeated is not None
                            else "its result is earlier in this conversation. Make a "
                            "different call or finish the investigation."
                        )
                    ),
                }
                if repeated is not None:
                    feedback["result"] = self._clip(repeated)
                logger.warning("Skipped duplicate {} call locally.", action.tool)
            elif action.tool == KNOWLEDGE_TOOL and self.knowledge is not None:
                seen_calls[call_key] = turn
                knowledge_searches += 1
                if knowledge_searches > self.knowledge_calls:
                    feedback = {
                        "status": "rejected",
                        "message": "Knowledge search limit reached for this task.",
                    }
                else:
                    records = self.knowledge.search(
                        str(action.arguments.get("query", "")),
                        str(action.arguments.get("kind") or "detections"),
                    )
                    feedback = {"status": "ok", "result": records or "no matching records"}
                logger.info("Knowledge search {!r}.", action.arguments.get("query"))
            elif action.tool == HYPOTHESES_NAME and self.hypotheses:
                seen_calls[call_key] = turn
                hypothesis_updates += 1
                if hypothesis_updates > HYPOTHESIS_UPDATES:
                    consecutive_skips += 1
                    feedback = {
                        "status": "rejected",
                        "message": "Hypothesis update limit reached; investigate or report.",
                    }
                else:
                    feedback = board.update(
                        action.arguments.get("items") or [],
                        case_file.entities.keys() | case_file.relations.keys(),
                    )
                step["board"] = board.render()
            elif id_problem is None and action.tool in COMPOSITE_TOOLS:
                seen_calls[call_key] = turn
                feedback, spent, new_objects = await self._run_composite(
                    action,
                    session,
                    catalog,
                    case_file,
                    registry,
                    seen_calls,
                    turn,
                    budget=max(1, self.max_steps - tool_calls - 1),
                )
                tool_calls += spent
                consecutive_skips = 0
                step["new_objects"] = new_objects
                step["runtime_calls"] = spent
                # Kept on the step for trace review; the model does not need them.
                step["inner_rewards"] = feedback.pop("inner_rewards", [])
                stale_calls = stale_calls + 1 if new_objects == 0 else 0
                if detections := self._match_detections(case_file):
                    feedback["knowledge"] = detections
                logger.info("Composite {} spent {} runtime calls.", action.tool, spent)
            elif id_problem is None and (empty := _covered_by_empty_search(action, empty_searches)):
                consecutive_skips += 1
                feedback = {
                    "status": "skipped",
                    "message": (
                        f"Search {empty!r} already returned nothing, and search matches "
                        "substrings, so a longer query containing it cannot match either. "
                        "Follow a relation or an open lead instead."
                    ),
                }
                logger.warning("Skipped search covered by an empty one: {}", empty)
            elif id_problem is None and (cached := case_file.cached(action.arguments)) is not None:
                seen_calls[call_key] = turn
                feedback = {
                    "status": "ok",
                    "result": self._clip(cached),
                    "note": "Answered from the case file; no tool call spent.",
                }
                logger.info("Answered {} from the case file.", action.tool)
            elif id_problem is None and action.tool == ad_tool and ad_lookups >= self.ad_lookups:
                consecutive_skips += 1
                feedback = {"status": "rejected", "message": AD_LIMIT_MESSAGE}
                logger.info("Rejected an Active Directory lookup over the per-task limit.")
            elif id_problem is not None:
                consecutive_skips += 1
                feedback = {"status": "rejected", "message": id_problem}
                logger.warning("Rejected {} call locally: {}", action.tool, id_problem)
            else:
                consecutive_skips = 0
                seen_calls[call_key] = turn
                if action.tool == ad_tool:
                    ad_lookups += 1
                response = await session.call_tool(action.tool, action.arguments)
                tool_calls += 1
                result = compact(_raw_result(response))
                feedback = self._tool_feedback(response, result)
                step["reward"] = response.reward
                registry.observe(result, ad_context="ad_object" in action.tool)
                new_objects = case_file.observe(result, ad_context="ad_object" in action.tool)
                case_file.record_search(action.arguments, result)
                if signals := case_file.signals(case_file.last_entities):
                    feedback["signals"] = signals
                if detections := self._match_detections(case_file):
                    feedback["knowledge"] = detections
                if guides := self._new_guides(case_file, case_file.last_entities, attached_guides):
                    feedback["playbooks"] = guides
                step["new_objects"] = new_objects
                if _is_search(action) and isinstance(result, dict) and not result.get("results"):
                    empty_searches.append(action.arguments)
                if entity_id := _single_entity_lookup(action.arguments):
                    overview = case_file.relation_overview(entity_id)
                    if overview["known"]:
                        feedback["relations_already_known"] = overview["known"]
                    if overview["unfetched"] >= SEARCH_HINT_RELATIONS:
                        feedback["hint"] = (
                            f"{overview['unfetched']} relations are unfetched. To reach related "
                            "entities, search the values this entity shares with them (path, "
                            "hash, account, address, hostname, command fragment); list its "
                            "relations by id only when you need the type of a link, and never "
                            "open them one by one with the relation tool."
                        )
                stale_calls = stale_calls + 1 if new_objects == 0 else 0
                # A new strong signal is a fork in the investigation: reason about it.
                strong_now = len(case_file.strong_signals())
                new_strong_signal, strong_seen = strong_now > strong_seen, strong_now
                # Scoping is decided during the investigation, not at the report: with the
                # first sign of an attack, show how to look for the hosts and accounts it
                # reached.
                if new_strong_signal and (
                    scope_guide := self._guide_once("attack-scope", attached_guides)
                ):
                    feedback.setdefault("playbooks", {})["attack-scope"] = scope_guide
                logger.info("Tool {} returned status {}.", action.tool, feedback["status"])
                if feedback["status"] == "error":
                    logger.warning(
                        "Tool {} failed: {}",
                        action.tool,
                        render_json(feedback.get("error") or feedback.get("result"))[:2_000],
                    )
                if response.task_result is not None:
                    step["status"] = feedback["status"]
                    return TaskResult.model_validate(response.task_result)

            step.update(status=feedback["status"], feedback=feedback)
            feedback["tool_calls_used"] = tool_calls
            if soft_steps is not None and tool_calls >= soft_steps:
                feedback["budget_warning"] = (
                    f"{tool_calls} calls used. Calls that find nothing for the report lower the "
                    "score. Submit the final report now unless one specific missing piece "
                    "decides the verdict or the report."
                )
            if (
                checkpoint_after is not None
                and tool_calls >= checkpoint_after
                and (tool_calls - checkpoint_after) % CHECKPOINT_EVERY == 0
                and feedback.get("status") != "skipped"
                and checkpoint_at != tool_calls
            ):
                checkpoint_at = tool_calls
                checkpoint_due = True
                feedback["checkpoint"] = CHECKPOINT_PROMPT
                if board.items:
                    feedback["hypotheses"] = board.render()
                if strong := case_file.strong_signals()[:MAX_CHECKPOINT_SIGNALS]:
                    feedback["checkpoint"] += (
                        " Strong signals in the case file - a benign conclusion has to answer "
                        "each of them with evidence: " + "; ".join(strong)
                    )
            if stale_calls >= LEADS_AFTER_STALE_CALLS or "budget_warning" in feedback:
                feedback["open_leads"] = case_file.open_leads() or (
                    "none: every suspicious entity and its neighbourhood is explored; finish"
                )
            if stale_calls >= stale_warn:
                feedback["progress_warning"] = (
                    f"The last {stale_calls} calls found no new entity or relation. The "
                    "evidence is likely complete: submit the final report."
                )
            messages.append(
                {"role": "tool", "content": render_json(feedback), "tool_call_id": call_id}
            )
            if sum(len(str(message.get("content") or "")) for message in messages) > (
                self.context_max_chars
            ):
                _compact_history(messages, task_prompt, case_file, self.context_max_chars // 2)
                logger.info("Compacted history into a case file of {} objects.", case_file.size)

        raise RuntimeError(f"Agent hit the {self.max_steps}-call limit without {FINISH_TOOL}.")

    async def _sweep_host(
        self,
        session: RemoteBenchmarkSession,
        catalog: ToolCatalog,
        alert: Any,
        case_file: CaseFile,
        registry: IdRegistry,
        steps: list[dict[str, Any]],
        seen_calls: dict[str, int],
    ) -> tuple[str, int]:
        """Open the first views every triage starts from, before the model's first turn.

        The alert host's process timeline around the alert time, then the logon
        context: who logged on to the host and from where, and which hosts the
        alert's account logged on to. They are ordinary searches, recorded as steps.

        Returns:
            The tables for the task prompt (empty when nothing was found) and the
            runtime calls spent.
        """
        if isinstance(alert, dict) and isinstance(alert.get("alert_text"), dict):
            alert = alert["alert_text"]
        tool = next(
            (
                name
                for name, spec in catalog.specs.items()
                if "query" in spec.parameters.get("required", [])
            ),
            None,
        )
        if not isinstance(alert, dict) or tool is None:
            return "", 0
        calls = 0

        async def search(
            arguments: dict[str, Any], tool_name: str | None = None
        ) -> dict[str, Any] | None:
            nonlocal calls
            name = tool_name or tool
            ad_context = name == ad_tool
            arguments, error = catalog.validate(name, arguments)
            if error is not None:
                logger.warning("Automatic call rejected locally: {}", error)
                return None
            try:
                response = await session.call_tool(name, arguments)
            except Exception as exc:
                logger.warning("Automatic call failed: {}", exc)
                return None
            calls += 1
            result = compact(_raw_result(response))
            registry.observe(result, ad_context=ad_context)
            new_objects = case_file.observe(result, ad_context=ad_context)
            case_file.record_search(arguments, result)
            self._match_detections(case_file)
            seen_calls[_call_key(AgentAction(tool=name, arguments=arguments))] = 0
            steps.append(
                {
                    "turn": 0,
                    "tool": name,
                    "arguments": arguments,
                    "status": response.info.get("tool_status", "unknown"),
                    "new_objects": new_objects,
                    "reward": response.reward,
                    "auto": True,
                    "feedback": {"result": self._clip(result)},
                }
            )
            return result if isinstance(result, dict) else None

        ad_tool = _runtime_tool(catalog, "ad_object_id")

        sections = []
        if self.host_sweep_pages > 0 and (base := sweep_arguments(alert)) is not None:
            trigger_ids = {
                entity["id"]
                for entity in alert.get("trigger_entities") or []
                if isinstance(entity, dict) and isinstance(entity.get("id"), str)
            }
            # The trigger's own logon session first: the activity next to the alert
            # shares it, background services do not. Each view gets one page, the
            # part from the trigger's start on before the hour before it; pages left
            # over go to the host.
            logon_id = session_query(alert)
            scopes = [("session", {**base, "query": logon_id})] if logon_id else []
            scopes.append(("host", base))
            views = [
                (scope, part, arguments)
                for scope, whole in scopes
                for part, arguments in (
                    split_window(whole) if self.sweep_split else [("around the alert", whole)]
                )
            ]
            pages_left = self.host_sweep_pages
            seen: set[str] = set()
            for scope, part, arguments in views:
                if pages_left <= 0:
                    break
                result = await search(arguments)
                pages_left -= 1
                found = [
                    node
                    for node in (result or {}).get("results") or []
                    if isinstance(node, dict) and node.get("id") not in seen
                ]
                seen |= {str(node.get("id")) for node in found}
                if lines := render_sweep(found, case_file, trigger_ids):
                    window = arguments["time_window"]
                    shown = {k: v for k, v in arguments.items() if k != "reasoning"}
                    title = (
                        f"Processes of the trigger's logon session {logon_id}"
                        if scope == "session"
                        else "Host timeline"
                    )
                    more = (result or {}).get("next_page_id")
                    header = (
                        f"{title}, {part} ({tool} {render_json(shown)}, {len(lines)} "
                        f"processes from {window['from']} to {window['to']}"
                        + ("; more on page 2" if more else "")
                        + f"). {SWEEP_NOTE}"
                    )
                    sections.append("\n".join([header, *lines]))
        if self.account_context and (
            account := await self._account_context(search, alert, ad_tool)
        ):
            sections.append(account)
        if self.logon_sweep and (host := alert_host(alert)) and isinstance(host.get("id"), str):
            sections += await self._logon_context(search, alert, host["id"], case_file)
        logger.info("Pre-investigation sweeps: {} sections in {} calls.", len(sections), calls)
        return "\n\n".join(sections), calls

    async def _account_context(
        self, search: Any, alert: dict[str, Any], ad_tool: str | None
    ) -> str | None:
        """The account the trigger ran as, with its directory object.

        Who the account is and what it is for (description, groups, privilege) is what
        tells sanctioned automation and administration from abuse of the same commands.
        """
        if (account := account_query(alert)) is None:
            return None
        query, user_type = account
        result = await search(
            {
                "reasoning": ACCOUNT_REASONING,
                "query": query,
                "scope": {"kind": "entity", "type": user_type},
            }
        )
        users = [
            node
            for node in (result or {}).get("results") or []
            if isinstance(node, dict) and node.get("type") == user_type
        ]
        if len(users) != 1:
            return None
        user = users[0]
        lines = [
            f"Account of the trigger ({user.get('id')}): " + render_json(user.get("properties", {}))
        ]
        ad_id = (user.get("properties") or {}).get("ad_object_id")
        # The account entity is report evidence; its directory object never was in
        # practice, so it is opened only when asked for.
        if self.account_directory and ad_tool and isinstance(ad_id, str):
            directory = await search(
                {"reasoning": ACCOUNT_REASONING, "ad_object_id": ad_id}, tool_name=ad_tool
            )
            if directory:
                lines.append(f"Its directory object ({ad_id}): " + render_json(directory))
        return f"{ACCOUNT_NOTE}\n" + "\n".join(lines)

    async def _logon_context(
        self,
        search: Any,
        alert: dict[str, Any],
        host_id: str,
        case_file: CaseFile,
    ) -> list[str]:
        """Logons to the alert host, and the hosts the alert's account logged on to."""
        sections = []
        result = await search(
            {"reasoning": LOGON_REASONING, "query": host_id, "scope": LOGON_SCOPE}
        )
        if lines := render_logons((result or {}).get("results") or [], case_file, host_id):
            sections.append(f"Logons to the alert host. {LOGON_NOTE}\n" + "\n".join(lines))
        if (account := account_query(alert)) is None:
            return sections
        query, user_type = account
        result = await search(
            {
                "reasoning": LOGON_REASONING,
                "query": query,
                "scope": {"kind": "entity", "type": user_type},
            }
        )
        users = [
            node
            for node in (result or {}).get("results") or []
            if isinstance(node, dict) and node.get("type") == user_type
        ]
        if len(users) != 1:
            return sections
        user_id = str(users[0].get("id"))
        result = await search(
            {"reasoning": LOGON_REASONING, "query": user_id, "scope": LOGON_SCOPE}
        )
        relations = [
            relation
            for relation in (result or {}).get("results") or []
            if isinstance(relation, dict) and relation.get("target_id") != host_id
        ]
        name = render_json(users[0].get("properties", {}).get("username", user_id))
        if lines := render_logons(relations, case_file, user_id):
            sections.append(
                f"Other hosts the alert's account {name} ({user_id}) logged on to. "
                f"{SPREAD_NOTE}\n" + "\n".join(lines)
            )
        else:
            sections.append(f"The alert's account {name} ({user_id}) has no logon to another host.")
        return sections

    async def _wait_for_llm(self) -> None:
        """Pause the queue until the LLM provider answers again."""
        wait = getattr(self.llm, "wait_until_available", None)
        if wait is None:
            return
        logger.warning("Pausing the queue until the LLM provider is back.")
        if not await wait(self.llm_recovery_wait_seconds):
            raise RuntimeError("The LLM provider did not come back; stopping the run.")

    def _new_guides(
        self,
        case_file: CaseFile,
        entity_ids: list[str],
        attached: set[str],
        is_trigger: bool = False,
    ) -> dict[str, str]:
        """Guides the given entities trigger that this task has not seen yet."""
        if self.knowledge is None:
            return {}
        found: dict[str, str] = {}
        for entity_id in dict.fromkeys(entity_ids):
            entry = case_file.entities.get(entity_id, {})
            for stem in self.knowledge.match_guides(
                entry.get("type"), entry.get("properties", {}), entry.get("signals", []), is_trigger
            ):
                if stem not in attached and (text := self.knowledge.guide(stem)):
                    attached.add(stem)
                    found[stem] = text
        return found

    def _guide_once(self, stem: str, attached: set[str]) -> str | None:
        """A guide's text the first time this task asks for it."""
        if self.knowledge is None or stem in attached:
            return None
        text = self.knowledge.guide(stem)
        if text:
            attached.add(stem)
        return text

    def _match_detections(self, case_file: CaseFile) -> dict[str, list[str]]:
        """Match newly seen entities against detection conditions once each."""
        if self.knowledge is None or not self.detections:
            return {}
        matched = {}
        for entity_id in dict.fromkeys(case_file.last_entities):
            entry = case_file.entities.get(entity_id, {})
            if entry.get("type") not in MATCHABLE_TYPES or "detections" in entry:
                continue
            entry["detections"] = self.knowledge.match_entity(
                entry.get("type"), entry.get("properties", {})
            )
            if entry["detections"]:
                matched[entity_id] = entry["detections"]
        return matched

    async def _review(
        self,
        messages: list[dict[str, Any]],
        catalog: ToolCatalog,
        draft: AgentAction,
        case_file: CaseFile,
        attached_guides: set[str] | None = None,
        stacking: str = "",
        trigger_ids: set[str] | None = None,
    ) -> tuple[AgentAction, dict[str, Any] | None, str | None]:
        """Assess the chain, derive the verdict in code, then write the report.

        The model states how close the chain came to an unacceptable event and
        explains every strong signal; the verdict follows from that assessment by
        rule, so suspicious facts cannot be explained away one at a time. Both LLM
        calls run in thinking mode: they cost time, not score.

        Args:
            messages: Conversation so far.
            catalog: Tools advertised for the task.
            draft: The finishing call the model proposed.
            case_file: Everything established so far.

        Returns:
            The final finishing call, the assessment and the derived verdict; the draft
            with no assessment if the review fails.
        """
        signals = case_file.strong_signals()[:MAX_LISTED_SIGNALS]
        assess_messages = [
            *messages,
            {
                "role": "user",
                "content": f"{ASSESS_PROMPT}\n"
                + ("\n".join(signals) or "none")
                + (f"\n\n{STACK_NOTE}\n{stacking}" if stacking else "")
                + (
                    f"\n\n{COVERAGE_NOTE}\n" + "\n".join(coverage)
                    if (coverage := case_file.coverage())
                    else ""
                ),
            },
        ]
        try:
            draft_verdict = (draft.arguments.get("submission") or {}).get("verdict")
            assessment, decision, consensus = await self._assess(
                assess_messages, case_file, draft_verdict
            )
            if draft_verdict in VERDICTS and decision.verdict != draft_verdict:
                # The investigation and the assessment disagree: weigh the report's own
                # case explicitly once, whichever way it points.
                reconcile_messages = [
                    *assess_messages,
                    {
                        "role": "user",
                        "content": RECONCILE_PROMPT.format(
                            draft=draft_verdict,
                            derived=decision.verdict,
                            reasoning=str(
                                (draft.arguments.get("submission") or {}).get("reasoning", "")
                            )[:4000],
                        ),
                    },
                ]
                reconciled = (
                    await self.llm.next_action(
                        reconcile_messages,
                        ASSESS_CATALOG,
                        force_tool="assess_chain",
                        thinking=True,
                    )
                ).arguments
                reconciled_decision = decide(reconciled, case_file, draft_verdict)
                consensus["reconcile"] = {
                    "from": decision.verdict,
                    "to": reconciled_decision.verdict,
                }
                logger.info(
                    "Reconciled draft {} with assessment {}: {}.",
                    draft_verdict,
                    decision.verdict,
                    reconciled_decision.verdict,
                )
                assessment, decision = reconciled, reconciled_decision
            verdict = decision.verdict
            candidates = {
                **decision.summary(),
                "artifact_candidates": decision.artifact_candidates(case_file),
                **(
                    {"tied_to_alert": tied, "tied_to_alert_note": LINKAGE_NOTE}
                    if (tied := linked_entities(case_file, trigger_ids or set()))
                    else {}
                ),
                "legitimacy_evidence_candidates": decision.evidence_candidates(case_file),
            }
            report_guide = self._guide_once(
                "attack-scope" if verdict == "malicious" else "legitimacy-evidence",
                attached_guides if attached_guides is not None else set(),
            )
            if report_guide:
                candidates["playbook"] = report_guide
            final_messages = [
                *messages,
                {
                    "role": "user",
                    "content": f"{FINAL_PROMPT.format(verdict=verdict)}\n{render_json(candidates)}"
                    f"\n\nYour assessment:\n{render_json(assessment)}"
                    f"\n\nYour earlier draft:\n{render_json(draft.arguments)}",
                },
            ]
            signal_evidence = decision.evidence_candidates(case_file)
            final, report_votes = await self._write_report(
                final_messages, catalog, verdict, case_file, signal_evidence
            )
            consensus["report_votes"] = report_votes
        except Exception as exc:
            logger.warning("Chain assessment failed, submitting the draft: {}", exc)
            return draft, None, None
        logger.info(
            "Chain assessment ({}): proximity={} target={} accepted stages={} explanations={} "
            "rejected={} unexplained={} -> {}.",
            consensus["mode"],
            assessment.get("proximity"),
            assessment.get("target_event"),
            len(decision.grounded_stages),
            len(decision.verified_explanations),
            len(decision.rejected),
            len(decision.unexplained_signals),
            verdict,
        )
        return (
            final,
            {**assessment, "decision": decision.summary(), "consensus": consensus},
            verdict,
        )

    async def _run_composite(
        self,
        action: AgentAction,
        session: RemoteBenchmarkSession,
        catalog: ToolCatalog,
        case_file: CaseFile,
        registry: IdRegistry,
        seen_calls: dict[str, int],
        turn: int,
        *,
        budget: int,
    ) -> tuple[dict[str, Any], int, int]:
        """Run a composite tool through ordinary runtime calls.

        Returns:
            Feedback for the model, runtime calls spent and new objects found.
        """
        search_tool = _runtime_tool(catalog, "query")
        entity_tool = _runtime_tool(catalog, "entity_id")
        spent = 0
        found = 0
        rewards: list[float] = []
        reasoning = str(action.arguments.get("reasoning") or action.tool)

        async def call(tool: str | None, arguments: dict[str, Any]) -> Any:
            nonlocal spent, found
            if tool is None or spent >= budget:
                return None
            arguments, error = catalog.validate(tool, {"reasoning": reasoning, **arguments})
            if error is not None:
                logger.warning("Composite step rejected locally: {}", error)
                return None
            key = _call_key(AgentAction(tool=tool, arguments=arguments))
            response = await session.call_tool(tool, arguments)
            spent += 1
            rewards.append(float(response.reward or 0.0))
            seen_calls.setdefault(key, turn)
            result = compact(_raw_result(response))
            registry.observe(result)
            found += case_file.observe(result)
            case_file.record_search(arguments, result)
            return result

        if action.tool == "prevalence":
            value = str(action.arguments.get("value", ""))
            result = await call(search_tool, {"query": value})
            summary = summarize_prevalence(value, result, case_file)
            feedback = {"status": "ok", "result": summary, "runtime_calls": spent}
            return {**feedback, "inner_rewards": rewards}, spent, found

        entity_id = str(action.arguments.get("entity_id"))
        depth = int(action.arguments.get("depth") or 3)
        if "properties" not in case_file.entities.get(entity_id, {}):
            await call(entity_tool, {"entity_id": entity_id})
        ancestors: list[str] = []
        children: list[str] = []
        current = entity_id
        for level in range(depth):
            result = await call(search_tool, {"query": current, "scope": PROCESS_CREATE})
            if result is None:
                break
            parent, kids = creation_links(result, current)
            if level == 0:
                children = kids
            if not parent or parent in ancestors or parent == entity_id:
                break
            if "properties" not in case_file.entities.get(parent, {}):
                await call(entity_tool, {"entity_id": parent})
            ancestors.append(parent)
            current = parent
        tree = render_tree(ancestors, entity_id, children, case_file)
        feedback = {"status": "ok", "result": tree, "runtime_calls": spent}
        return {**feedback, "inner_rewards": rewards}, spent, found

    async def _write_report(
        self,
        final_messages: list[dict[str, Any]],
        catalog: ToolCatalog,
        verdict: str,
        case_file: CaseFile | None = None,
        signal_evidence: list[dict[str, Any]] | None = None,
    ) -> tuple[AgentAction, dict[str, Any]]:
        """Write the report several times independently and keep what they agree on.

        Returns:
            The merged finishing call and the vote counts.

        Raises:
            Exception: If no report could be written.
        """
        if verdict == "benign" and self.report_form and case_file is not None:
            form_messages = [*final_messages, {"role": "user", "content": FORM_PROMPT}]
            results = await asyncio.gather(
                *(
                    self.llm.next_action(
                        form_messages, FORM_CATALOG, force_tool=FORM_NAME, thinking=True
                    )
                    for _ in range(self.report_samples)
                ),
                return_exceptions=True,
            )
            built = [
                report
                for result in results
                if isinstance(result, AgentAction)
                and (report := build_benign_report(result.arguments, case_file, signal_evidence))
                is not None
            ]
            if built:
                merged, votes = vote_reports(built, verdict)
                arguments, error = catalog.validate(FINISH_TOOL, merged)
                if error is None:
                    logger.info("Benign report from {} forms: {}.", len(built), votes)
                    return AgentAction(tool=FINISH_TOOL, arguments=arguments), {
                        **votes,
                        "form": True,
                    }
                logger.warning("Form report failed validation, writing it freely: {}", error)
            else:
                logger.warning("No usable legitimacy form, writing the report freely.")
        results = await asyncio.gather(
            *(
                self.llm.next_action(final_messages, catalog, force_tool=FINISH_TOOL, thinking=True)
                for _ in range(self.report_samples)
            ),
            return_exceptions=True,
        )
        reports = [result for result in results if isinstance(result, AgentAction)]
        if not reports:
            raise next(result for result in results if isinstance(result, BaseException))
        merged, votes = vote_reports([report.arguments for report in reports], verdict)
        arguments, error = catalog.validate(FINISH_TOOL, merged)
        if error is not None:
            logger.warning("Merged report failed validation, using one sample: {}", error)
            return reports[0], {**votes, "merged": False}
        logger.info("Report votes: {}.", votes)
        return reports[0].model_copy(update={"arguments": arguments}), votes

    async def _stack(
        self,
        session: RemoteBenchmarkSession,
        catalog: ToolCatalog,
        case_file: CaseFile,
        registry: IdRegistry,
        trigger_ids: set[str],
        seen_calls: dict[str, int],
        steps: list[dict[str, Any]] | None = None,
    ) -> tuple[str, int]:
        """Count how often the shape of each key command occurs in the graph.

        Returns:
            One line per key process (empty when there is none) and the calls spent.
        """
        tool = _runtime_tool(catalog, "query")
        if tool is None:
            return "", 0
        lines = []
        spent = 0
        for entity_id in key_processes(case_file, trigger_ids):
            fragment = stable_fragment(case_file.entities[entity_id]["properties"])
            if fragment is None:
                continue
            arguments, error = catalog.validate(
                tool,
                {
                    "query": fragment,
                    "scope": {"kind": "entity", "type": case_file.entities[entity_id]["type"]},
                    "reasoning": STACK_REASONING,
                },
            )
            if error is not None:
                continue
            try:
                response = await session.call_tool(tool, arguments)
            except Exception as exc:
                logger.warning("Stacking search failed: {}", exc)
                continue
            spent += 1
            seen_calls.setdefault(_call_key(AgentAction(tool=tool, arguments=arguments)), 0)
            if steps is not None:
                steps.append(
                    {
                        "turn": 0,
                        "tool": tool,
                        "arguments": arguments,
                        "reward": response.reward,
                        "auto": True,
                        "stacking": True,
                    }
                )
            result = compact(_raw_result(response))
            registry.observe(result)
            case_file.observe(result)
            case_file.record_search(arguments, result)
            lines.append(summarize_stack(entity_id, case_file, fragment, result))
        if lines:
            logger.info("Stacking: {} commands in {} calls.", len(lines), spent)
        return "\n".join(lines), spent

    async def _assess(
        self,
        assess_messages: list[dict[str, Any]],
        case_file: CaseFile,
        draft_verdict: str | None = None,
    ) -> tuple[dict[str, Any], Any, dict[str, Any]]:
        """Sample independent assessments; break a tie when their verdicts disagree.

        LLM calls cost time, not score, so the verdict on an ambiguous case is not
        left to one sample: agreement is accepted as is, disagreement is resolved by
        a further assessment that sees every sample and what the code accepted.

        Returns:
            The chosen assessment, its checked decision and a consensus record.

        Raises:
            Exception: If no assessment could be obtained.
        """
        results = await asyncio.gather(
            *(
                self.llm.next_action(
                    assess_messages, ASSESS_CATALOG, force_tool="assess_chain", thinking=True
                )
                for _ in range(self.assess_samples)
            ),
            return_exceptions=True,
        )
        samples = [result.arguments for result in results if isinstance(result, AgentAction)]
        if not samples:
            raise next(result for result in results if isinstance(result, BaseException))
        decisions = [decide(sample, case_file, draft_verdict) for sample in samples]
        verdicts = [decision.verdict for decision in decisions]
        consensus: dict[str, Any] = {"samples": len(samples), "verdicts": verdicts}
        if len(set(verdicts)) == 1:
            consensus["mode"] = "agreed" if len(samples) > 1 else "single"
            return samples[0], decisions[0], consensus

        briefs = [
            {"verdict": decision.verdict, **decision.summary(), "assessment": sample}
            for sample, decision in zip(samples, decisions, strict=True)
        ]
        tie_messages = [
            *assess_messages,
            {"role": "user", "content": f"{TIE_BREAK_PROMPT}\n{render_json(briefs)}"},
        ]
        tie = (
            await self.llm.next_action(
                tie_messages, ASSESS_CATALOG, force_tool="assess_chain", thinking=True
            )
        ).arguments
        tie_decision = decide(tie, case_file, draft_verdict)
        consensus.update(mode="tie_break", tie_break_verdict=tie_decision.verdict)
        return tie, tie_decision, consensus

    def _tool_feedback(self, response: ToolCallResult, result: Any) -> dict[str, Any]:
        """Reduce a runtime response to the evidence the LLM needs.

        The full observation is never echoed back: it repeats the whole tool
        catalog and would grow the context on every step.

        Args:
            response: Server tool-call response.
            result: Compacted tool result.

        Returns:
            Compact status, result and error.
        """
        feedback: dict[str, Any] = {
            "status": response.info.get("tool_status", "unknown"),
            "result": self._clip(result),
        }
        error = response.info.get("error")
        if error:
            feedback["error"] = error
        return feedback

    def _clip(self, value: Any) -> Any:
        """Truncate oversized tool results, keeping small structured ones intact."""
        text = value if isinstance(value, str) else render_json(value)
        if len(text) <= self.tool_result_max_chars:
            return value
        omitted = len(text) - self.tool_result_max_chars
        return f"{text[: self.tool_result_max_chars]}... [truncated {omitted} chars]"


def _is_search(action: AgentAction) -> bool:
    """A substring search, recognised by its arguments rather than the tool name."""
    return isinstance(action.arguments.get("query"), str) and action.tool != KNOWLEDGE_TOOL


def _covered_by_empty_search(
    action: AgentAction,
    empty_searches: list[dict[str, Any]],
) -> str | None:
    """Return the earlier empty query that proves this search is empty too.

    Search matches substrings, so if query Q found nothing, any query containing Q
    finds nothing under the same or a narrower scope and time window.
    """
    if not _is_search(action):
        return None
    query = action.arguments["query"].lower()
    for earlier in empty_searches:
        same_filters = all(
            earlier.get(key) is None or earlier.get(key) == action.arguments.get(key)
            for key in ("scope", "time_window")
        )
        if same_filters and earlier["query"].lower() in query:
            return str(earlier["query"])
    return None


def _disagreement_message(
    draft_verdict: str, derived_verdict: str, assessment: dict[str, Any] | None
) -> str:
    """Ask for the fact that decides between the draft and the assessment."""
    decision = (assessment or {}).get("decision") or {}
    unexplained = decision.get("unexplained_signals") or []
    found = (
        f"{decision.get('accepted_stages', 0)} attacker steps accepted, "
        f"{len(unexplained)} signals left unexplained"
    )
    if draft_verdict == "malicious":
        check = (
            "Your draft describes an attack, but no step of it is shown by the graph yet. "
            "Look at what the suspicious step actually did next - the processes it "
            "started, the files it wrote, the connections it made, the logons that "
            "followed."
        )
    else:
        check = (
            "Your draft finds the activity legitimate, but the assessment could not explain "
            "these signals: " + "; ".join(str(signal) for signal in unexplained[:5]) + "."
            " Look up the facts that would explain them or show them to be part of an "
            "attack."
        )
    return (
        f"Your draft concluded {draft_verdict}; the chain assessment came out "
        f"{derived_verdict} ({found}). {check} Use the fewest calls, then submit the "
        "report again."
    )


def _redirect_lookup(
    action: AgentAction, registry: IdRegistry, catalog: ToolCatalog
) -> AgentAction:
    """Fix a single-id lookup whose id is mistyped or belongs to another kind of object.

    A mis-copied id is replaced by the one known id it nearly matches; an id of the
    wrong kind (a relation id passed to the entity lookup) is sent to the catalog tool
    that takes that kind of id. The model's intent is kept and no call is wasted.
    """
    keys = set(action.arguments) - {"reasoning"}
    if len(keys) != 1 or (key := next(iter(keys))) not in ARGUMENT_ROLES:
        return action
    value = str(action.arguments[key])
    resolved = resolve_id(value, registry.seen) if registry.seen else value
    if resolved is None:
        return action
    role = registry.sole_role(resolved)
    target_key = ROLE_ARGUMENTS[role] if role else key
    tool = action.tool
    if target_key != key:
        candidates = [
            spec.name
            for spec in catalog.specs.values()
            if set(spec.parameters.get("required", [])) - {"reasoning"} == {target_key}
        ]
        if len(candidates) != 1:
            return action
        tool = candidates[0]
    if (tool, target_key, resolved) == (action.tool, key, value):
        return action
    arguments = {k: v for k, v in action.arguments.items() if k != key}
    arguments[target_key] = resolved
    arguments, error = catalog.validate(tool, arguments)
    if error is not None:
        return action
    logger.info("Redirected {}({}) to {}({}).", action.tool, value, tool, resolved)
    return action.model_copy(update={"tool": tool, "arguments": arguments})


def _relation_to_search(
    action: AgentAction,
    case_file: CaseFile,
    catalog: ToolCatalog,
    seen_calls: dict[str, int],
) -> AgentAction:
    """Open an unseen relation by listing its owner's relations instead.

    A relation lookup returns one edge and never a new entity. Its id comes from an
    entity's relation list, and one search for that entity's id returns every relation
    of it with types and endpoints, the asked one included, for the same one call.
    """
    relation_tool = _runtime_tool(catalog, "relation_id")
    search_tool = _runtime_tool(catalog, "query")
    if action.tool != relation_tool or search_tool is None:
        return action
    relation_id = str(action.arguments.get("relation_id", ""))
    if relation_id in case_file.relations:
        return action
    owner = next(
        (
            entity_id
            for entity_id, entry in case_file.entities.items()
            if any(
                relation_id in (entry.get("relation_ids") or {}).get(direction, [])
                for direction in ("incoming", "outgoing")
            )
        ),
        None,
    )
    if owner is None:
        return action
    arguments, error = catalog.validate(
        search_tool, {"query": owner, "reasoning": RELATION_SEARCH_REASONING}
    )
    if (
        error is not None
        or _call_key(AgentAction(tool=search_tool, arguments=arguments)) in seen_calls
    ):
        return action
    logger.info("Turned relation lookup {} into a search of its owner {}.", relation_id, owner)
    return action.model_copy(update={"tool": search_tool, "arguments": arguments})


def _valid_finish(catalog: ToolCatalog, arguments: dict[str, Any]) -> bool:
    """Whether code-rewritten report arguments still fit the finishing tool's schema."""
    _, error = catalog.validate(FINISH_TOOL, arguments)
    if error is not None:
        logger.warning("Rewritten report does not fit the tool schema, keeping it: {}", error)
    return error is None


def _runtime_tool(catalog: ToolCatalog, argument: str) -> str | None:
    """The runtime tool whose only required argument besides reasoning is `argument`."""
    for name, spec in catalog.specs.items():
        if set(spec.parameters.get("required", [])) - {"reasoning"} == {argument}:
            return name
    return None


def _single_entity_lookup(arguments: dict[str, Any]) -> str | None:
    """Entity id of a plain entity lookup, whatever the tool is called."""
    if set(arguments) - {"reasoning"} == {"entity_id"}:
        return str(arguments["entity_id"])
    return None


def _raw_result(response: ToolCallResult) -> Any:
    """Return the tool result from `info`, falling back to the observation."""
    result = response.info.get("tool_result")
    return response.observation.get("last_tool_result") if result is None else result


def _compact_history(
    messages: list[dict[str, Any]],
    task_prompt: str,
    case_file: CaseFile,
    max_chars: int,
) -> None:
    """Replace old raw tool results with the case file to bound the context.

    Runs only when the history crosses the size limit, so the provider's prefix
    cache stays valid between compactions.

    Args:
        messages: Conversation, modified in place.
        task_prompt: Original alert message.
        case_file: Everything established so far.
        max_chars: Size budget for the rendered case file.
    """
    tool_indexes = [index for index, message in enumerate(messages) if message["role"] == "tool"]
    for index in tool_indexes[:-KEEP_RECENT_RESULTS]:
        messages[index]["content"] = render_json({"result": COMPACTED_RESULT})
    messages[1]["content"] = (
        f"{task_prompt}\n\nCase file: every entity and relation found so far "
        f"(older raw tool results were condensed into it).\n{case_file.render(max_chars)}"
    )


def _public_context(observation: dict[str, Any]) -> dict[str, Any]:
    """Keep the alert and any other task context, minus the tool catalog."""
    return {
        key: value
        for key, value in observation.items()
        if key not in IGNORED_OBSERVATION_KEYS and value not in (None, "")
    }


def _call_key(action: AgentAction) -> str:
    """Identify a call by tool and arguments, ignoring the free-text reasoning."""
    arguments = {key: value for key, value in action.arguments.items() if key != "reasoning"}
    return f"{action.tool}:{render_json(arguments)}"


def _assistant_message(call_id: str, action: AgentAction) -> dict[str, Any]:
    """Build the assistant turn that carries one tool call."""
    return {
        "role": "assistant",
        "content": action.thought or None,
        "tool_calls": [
            {
                "type": "function",
                "id": call_id,
                "function": {"name": action.tool, "arguments": render_json(action.arguments)},
            }
        ],
    }
