import argparse
import asyncio
import json
import sys

import truststore
from pydantic import ValidationError

from bluesec1_agent.agent import InvestigationAgent
from bluesec1_agent.knowledge import default_knowledge
from bluesec1_agent.llm import OpenAIToolCallingClient
from bluesec1_agent.settings import Settings
from bluesec1_client import (
    CompetitionClosedError,
    RemoteAuthenticationError,
    RemoteBenchmarkClient,
    RemoteRateLimitError,
    RemoteUnavailableError,
    RunCapacityExceededError,
)


def build_parser() -> argparse.ArgumentParser:
    """Build the remote-runtime command-line interface.

    Returns:
        Configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Run the tool-calling investigation agent against scenario-runtime."
    )
    parser.add_argument("--endpoint", help="Override SCENARIO_RUNTIME_ENDPOINT.")
    parser.add_argument("--token", help="Override SCENARIO_RUNTIME_TOKEN.")
    parser.add_argument("--run-label", help="Override REMOTE_RUN_LABEL.")
    parser.add_argument("--agent-name", help="Override AGENT_NAME.")
    parser.add_argument("--arena", help="Override SCENARIO_RUNTIME_ARENA.")
    parser.add_argument(
        "--verify-tls",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Override SCENARIO_RUNTIME_VERIFY_TLS.",
    )
    parser.add_argument(
        "--max-tasks",
        type=int,
        help="Stop after this many tasks instead of draining the queue (for debugging).",
    )
    return parser


async def run(args: argparse.Namespace) -> None:
    """Execute one new remote run and print its task results.

    Args:
        args: Parsed command-line arguments.
    """
    truststore.inject_into_ssl()
    settings = _load_settings()
    llm = OpenAIToolCallingClient(
        base_url=settings.llm_base_url,
        api_key=settings.llm_api_key.get_secret_value(),
        model=settings.llm_default_model,
        timeout_seconds=settings.llm_timeout_seconds,
        max_completion_tokens=settings.llm_max_completion_tokens,
        max_retries=settings.llm_max_step_retries,
        temperature=settings.llm_temperature,
        extra_body=settings.llm_extra_body,
        outage_wait_seconds=settings.llm_outage_wait_seconds,
    )
    agent_name = args.agent_name or settings.agent_name
    verify_tls = (
        settings.scenario_runtime_verify_tls if args.verify_tls is None else args.verify_tls
    )
    arena = args.arena or settings.scenario_runtime_arena
    # The runtime shows this name on the leaderboard; the real model stays local.
    public_model_name = settings.public_model_name or settings.llm_default_model
    async with (
        llm,
        RemoteBenchmarkClient(
            endpoint=args.endpoint or settings.scenario_runtime_endpoint,
            token=args.token or settings.scenario_runtime_token.get_secret_value(),
            verify_tls=verify_tls,
            run_label=args.run_label or settings.remote_run_label,
            agent_name=agent_name,
            model_name=public_model_name,
            arena=arena,
            metadata={
                "agent": agent_name,
                "implementation": "native-tool-calling-scenario-runtime-grpc",
                "model": public_model_name,
            },
        ) as client,
    ):
        result = await InvestigationAgent(
            llm,
            max_steps=settings.agent_max_steps,
            soft_steps=settings.agent_soft_steps,
            tool_result_max_chars=settings.agent_tool_result_max_chars,
            context_max_chars=settings.agent_context_max_chars,
            review_finish=settings.agent_review_finish,
            knowledge=(
                default_knowledge(settings.agent_knowledge_ranker)
                if settings.agent_knowledge
                else None
            ),
            knowledge_calls=settings.agent_knowledge_calls,
            llm_recovery_wait_seconds=settings.llm_recovery_wait_seconds,
            thinking=settings.agent_thinking,
            assess_samples=settings.agent_assess_samples,
            report_samples=settings.agent_report_samples,
            composite_tools=settings.agent_composite_tools,
            process_tree=settings.agent_process_tree,
            hypotheses=settings.agent_hypotheses,
            report_form=settings.agent_report_form,
            benign_shape=settings.agent_benign_shape,
            pace=settings.agent_pace,
            ad_lookups=settings.agent_ad_lookups,
            detections=settings.agent_detections,
            stacking=settings.agent_stacking,
            checkpoint_after=settings.agent_checkpoint_after,
            artifact_filter=settings.agent_artifact_filter,
            host_sweep_pages=settings.agent_host_sweep_pages,
            logon_sweep=settings.agent_logon_sweep,
            account_context=settings.agent_account_context,
            account_directory=settings.agent_account_directory,
            sweep_split=settings.agent_sweep_split,
            trajectory_dir=settings.agent_trajectory_dir,
            run_metadata={
                "agent_name": agent_name,
                "arena": arena,
                "model": settings.llm_default_model,
                "temperature": settings.llm_temperature,
                "extra_body": settings.llm_extra_body,
                "max_steps": settings.agent_max_steps,
                "soft_steps": settings.agent_soft_steps,
                "review_finish": settings.agent_review_finish,
                "knowledge": settings.agent_knowledge,
                "knowledge_ranker": settings.agent_knowledge_ranker,
                "thinking": settings.agent_thinking,
                "assess_samples": settings.agent_assess_samples,
                "report_samples": settings.agent_report_samples,
                "composite_tools": settings.agent_composite_tools,
                "process_tree": settings.agent_process_tree,
                "hypotheses": settings.agent_hypotheses,
                "report_form": settings.agent_report_form,
                "benign_shape": settings.agent_benign_shape,
                "pace": settings.agent_pace,
                "ad_lookups": settings.agent_ad_lookups,
                "detections": settings.agent_detections,
                "stacking": settings.agent_stacking,
                "checkpoint_after": settings.agent_checkpoint_after,
                "artifact_filter": settings.agent_artifact_filter,
                "host_sweep_pages": settings.agent_host_sweep_pages,
                "logon_sweep": settings.agent_logon_sweep,
                "account_context": settings.agent_account_context,
                "account_directory": settings.agent_account_directory,
                "sweep_split": settings.agent_sweep_split,
            },
        ).run(client, max_tasks=args.max_tasks)

    print(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))


def main() -> None:
    """Parse arguments and execute the async remote agent."""
    try:
        asyncio.run(run(build_parser().parse_args()))
    except RunCapacityExceededError as error:
        print(_run_capacity_message(error), file=sys.stderr)
        raise SystemExit(1) from error
    except CompetitionClosedError as error:
        print(
            "The selected competition arena is closed. Check SCENARIO_RUNTIME_ARENA or retry "
            "when the arena opens.",
            file=sys.stderr,
        )
        raise SystemExit(1) from error
    except RemoteRateLimitError as error:
        print(
            "Run starts are temporarily rate-limited. Wait before starting another run.",
            file=sys.stderr,
        )
        raise SystemExit(1) from error
    except RemoteAuthenticationError as error:
        print(
            "The runtime rejected your key. Check SCENARIO_RUNTIME_TOKEN in .env.",
            file=sys.stderr,
        )
        raise SystemExit(1) from error
    except RemoteUnavailableError as error:
        print(
            "Cannot reach the runtime. Check SCENARIO_RUNTIME_ENDPOINT and "
            "SCENARIO_RUNTIME_VERIFY_TLS in .env.",
            file=sys.stderr,
        )
        raise SystemExit(1) from error


def _load_settings() -> Settings:
    """Load settings and explain what is missing instead of raising a raw error.

    Returns:
        Validated settings.
    """
    try:
        return Settings()
    except ValidationError as error:
        missing = [str(item["loc"][0]) for item in error.errors() if item["type"] == "missing"]
        if not missing:
            raise
        print("Missing configuration: " + ", ".join(missing), file=sys.stderr)
        print(
            "Copy .env.example to .env and fill it in. "
            "Runtime address and key: https://bluesec.team/",
            file=sys.stderr,
        )
        raise SystemExit(1) from error


def _run_capacity_message(error: RunCapacityExceededError) -> str:
    """Explain which run limit was hit and what to do about it.

    Args:
        error: Capacity failure reported by the runtime.

    Returns:
        Message for the participant.
    """
    if getattr(error, "reason", None) == "PROCESS_ACTIVE_RUN_LIMIT_REACHED":
        lines = ["The runtime is at its overall capacity right now. This is not your limit."]
    else:
        lines = [
            "You have reached your limit of concurrent runs.",
            "Wait for a running one to finish. If an agent was killed mid-run, its run stays "
            "open until it is released.",
        ]
    return "\n".join(lines)
