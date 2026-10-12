"""Summarize saved agent trajectories so runs can be compared side by side.

Usage:
    uv run python scripts/summarize_runs.py [runs_dir] [--tasks]
"""

import argparse
import json
from collections import Counter
from pathlib import Path
from statistics import mean
from typing import Any


def load_run(run_dir: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Read run metadata and every task record in one run directory."""
    metadata_path = run_dir / "run.json"
    metadata = json.loads(metadata_path.read_text()) if metadata_path.exists() else {}
    tasks = [
        json.loads(path.read_text())
        for path in sorted(run_dir.glob("*.json"))
        if path.name != "run.json"
    ]
    return metadata, tasks


def submitted_verdict(task: dict[str, Any]) -> str:
    """Return the verdict of the last finishing call, or a failure marker."""
    for step in reversed(task.get("steps", [])):
        if step.get("tool") == "finish_investigation":
            submission = step.get("arguments", {}).get("submission", {})
            if isinstance(submission, dict):
                return str(submission.get("verdict", "?"))
    return "none"


def summarize(run_dir: Path, show_tasks: bool) -> None:
    """Print one run's aggregate metrics and, optionally, per-task rows."""
    metadata, tasks = load_run(run_dir)
    if not tasks:
        return
    results = [task.get("task_result", {}) for task in tasks]
    completed = [result for result in results if result.get("completion_reason") == "terminated"]

    def average(key: str) -> float:
        return float(mean(result.get(key, 0.0) for result in results))

    failed_calls = sum(
        step.get("status") == "error" for task in tasks for step in task.get("steps", [])
    )
    verdicts = Counter(submitted_verdict(task) for task in tasks)
    print(
        f"{run_dir.name}  {metadata.get('started_at', '')[:19]}  "
        f"model={metadata.get('model')}  arena={metadata.get('arena')}"
    )
    print(
        f"  tasks={len(tasks)} completed={len(completed)} "
        f"quality={average('quality_score'):.3f} efficiency={average('efficiency_score'):.3f} "
        f"reward={average('total_reward'):.3f} tool_calls={average('tool_calls'):.1f} "
        f"failed_calls={failed_calls} verdicts={dict(verdicts)}"
    )
    if show_tasks:
        for task, result in zip(tasks, results, strict=True):
            print(
                f"    {task['task_id'][:8]} {result.get('completion_reason', '?'):10} "
                f"verdict={submitted_verdict(task):9} q={result.get('quality_score', 0):.2f} "
                f"e={result.get('efficiency_score', 0):.2f} calls={result.get('tool_calls', 0)}"
                + (f"  error={task['agent_error'][:80]}" if task.get("agent_error") else "")
            )


def main() -> None:
    """Summarize every run directory, oldest first."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("runs_dir", nargs="?", default="runs", type=Path)
    parser.add_argument("--tasks", action="store_true", help="Also print per-task rows.")
    args = parser.parse_args()
    run_dirs = sorted(
        (path for path in args.runs_dir.iterdir() if path.is_dir()),
        key=lambda path: path.stat().st_mtime,
    )
    for run_dir in run_dirs:
        summarize(run_dir, args.tasks)


if __name__ == "__main__":
    main()
