"""Attribute each run's lost quality to failure categories, and compare runs.

Every task loses 1 - quality. This script puts each task into one failure category
from what its trajectory shows, sums the loss per category, and lines runs up side by
side, so the next harness change targets the most expensive category and is judged by
the same category afterwards.

Usage:
    uv run python scripts/failure_report.py <run prefix> [<run prefix> ...] [--tasks]
"""

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

# A wrong verdict costs far more reward than a weak report: -20 and below in practice.
WRONG_VERDICT_REWARD = -10.0
WEAK_BENIGN = 0.4
WEAK_MALICIOUS = 0.6
LONG_REPORT = 12
CORE_KINDS = ("host_to_isolate", "identity_to_rotate")


def final_step(task: dict[str, Any]) -> dict[str, Any] | None:
    """The submitted finishing call."""
    steps = [s for s in task.get("steps", []) if s.get("tool") == "finish_investigation"]
    return steps[-1] if steps else None


def scenario(task: dict[str, Any]) -> str:
    """A run-independent label for the task's scenario: trigger binary and parent."""
    try:
        alert = json.loads(task["observation"]["alert_text"])
    except (KeyError, TypeError, ValueError):
        return "?"
    trigger: dict[str, Any] = next(
        (e for e in alert.get("trigger_entities", []) if e.get("type") != "host"), {}
    )
    properties = trigger.get("properties") or {}
    name = str(properties.get("image_path") or alert.get("alert_description", "?"))
    parent = str(properties.get("parent_image") or "?")
    label = f"{name.split(chr(92))[-1]} <- {parent.split(chr(92))[-1]}".lower()
    return re.sub(r"\d+", "#", label)


def classify(task: dict[str, Any]) -> tuple[str, float]:
    """Failure category of one task and the quality it lost."""
    result = task.get("task_result", {})
    quality = float(result.get("quality_score") or 0.0)
    loss = 1.0 - quality
    if task.get("agent_error") or result.get("completion_reason") != "terminated":
        return "agent error / not finished", loss
    final = final_step(task)
    if final is None:
        return "no report", loss
    submission = final.get("arguments", {}).get("submission", {})
    verdict = submission.get("verdict")
    draft = ((final.get("draft_arguments") or {}).get("submission") or {}).get("verdict")
    decision = (final.get("assessment") or {}).get("decision") or {}
    if float(result.get("total_reward") or 0.0) <= WRONG_VERDICT_REWARD:
        if draft and draft != verdict:
            cause = "code overturned the draft"
            if not decision.get("accepted_stages") and decision.get("unexplained_signals"):
                cause = "code: unexplained signals, no stage"
        else:
            cause = "model"
        return f"wrong verdict -> {verdict} ({cause})", loss
    stalled = any("progress_warning" in (s.get("feedback") or {}) for s in task["steps"])
    if verdict == "benign":
        if quality == 0:
            return "benign: no evidence matched", loss
        if quality < WEAK_BENIGN:
            return "benign: weak evidence", loss
        return "benign: ok", loss
    artifacts = submission.get("ir_artifacts") or []
    kinds = Counter(str(a.get("kind")) for a in artifacts)
    if quality < WEAK_MALICIOUS:
        if not all(kinds[k] for k in CORE_KINDS):
            return "malicious: no host or account", loss
        if len(artifacts) > LONG_REPORT:
            return "malicious: long report (extras)", loss
        if stalled:
            return "malicious: stalled investigation", loss
        return "malicious: incomplete", loss
    return "malicious: ok", loss


def load(prefix: str, root: Path) -> tuple[str, list[dict[str, Any]]]:
    """Tasks of the run whose id starts with the prefix."""
    matches = [path for path in root.iterdir() if path.is_dir() and path.name.startswith(prefix)]
    if len(matches) != 1:
        raise SystemExit(f"{prefix!r} matches {len(matches)} runs")
    run = matches[0]
    tasks = [
        json.loads(path.read_text())
        for path in sorted(run.glob("*.json"))
        if path.name != "run.json"
    ]
    return run.name[:8], tasks


def main() -> None:
    """Print the loss table per category and the per-scenario quality of each run."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("runs", nargs="+", help="Run id prefixes, oldest first.")
    parser.add_argument("--root", type=Path, default=Path("runs"))
    parser.add_argument("--tasks", action="store_true", help="List tasks per category.")
    args = parser.parse_args()

    runs = [load(prefix, args.root) for prefix in args.runs]
    losses: dict[str, dict[str, float]] = defaultdict(dict)
    counts: dict[str, dict[str, int]] = defaultdict(dict)
    by_scenario: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    members: dict[str, list[str]] = defaultdict(list)
    for name, tasks in runs:
        for task in tasks:
            category, loss = classify(task)
            losses[category][name] = losses[category].get(name, 0.0) + loss
            counts[category][name] = counts[category].get(name, 0) + 1
            quality = float(task.get("task_result", {}).get("quality_score") or 0.0)
            by_scenario[scenario(task)][name].append(quality)
            members[category].append(
                f"{name} {task['task_id'][:8]} q={quality:.2f} {scenario(task)}"
            )

    names = [name for name, _ in runs]
    width = max(len(category) for category in losses) + 2
    print(f"{'lost quality by category':{width}}" + "".join(f"{n:>14}" for n in names))
    order = sorted(losses, key=lambda c: -sum(losses[c].values()))
    for category in order:
        cells = "".join(
            f"{losses[category].get(n, 0.0):>8.2f} ({counts[category].get(n, 0):>2})" for n in names
        )
        print(f"{category:{width}}{cells}")
    totals = "".join(
        f"{sum(losses[c].get(n, 0.0) for c in losses):>8.2f} ({len(t):>2})" for n, t in runs
    )
    print(f"{'total lost (tasks)':{width}}{totals}")

    if len(runs) > 1:
        print("\nper scenario, mean quality (runs that saw it)")
        for label in sorted(by_scenario):
            cells = "".join(
                f"{sum(v) / len(v):>14.2f}" if (v := by_scenario[label].get(n)) else f"{'-':>14}"
                for n in names
            )
            print(f"{label[:width]:{width}}{cells}")

    if args.tasks:
        for category in order:
            print(f"\n## {category}")
            for line in members[category]:
                print(f"  {line}")


if __name__ == "__main__":
    main()
