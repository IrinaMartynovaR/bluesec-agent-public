"""Review what the agent did, call by call, across runs.

For every task: the scenario, whether the verdict held, quality and efficiency, and
each runtime call classified by kind and by whether it opened report evidence (the
per-call reward). Aggregates show where calls go to waste: the tail after the last
useful call, streaks of fruitless calls, repeats, and the call kinds that rarely hit.

Usage:
    uv run python scripts/trace_review.py <run prefix> [...] [--json out.json]
"""

import argparse
import json
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from failure_report import classify, scenario  # noqa: E402

UUID_LENGTH = 36


def call_kind(step: dict[str, Any]) -> str:
    """A label for what kind of call a step was."""
    arguments = step.get("arguments") or {}
    tool = str(step.get("tool"))
    if step.get("stacking"):
        return "auto stacking"
    if step.get("auto"):
        return "auto sweep"
    if tool != "search":
        return tool
    query = str(arguments.get("query", ""))
    scope = arguments.get("scope")
    if len(query) == UUID_LENGTH and query.count("-") == 4:
        target = "by entity id"
    elif query.startswith("0x"):
        target = "by logon id"
    elif query.replace(".", "").isdigit():
        target = "by address"
    else:
        target = "by value"
    label = f"search {target}"
    if isinstance(scope, dict) and scope.get("type"):
        label += f" [{scope['type']}]"
    if arguments.get("page_id"):
        label += " (next page)"
    return label


def review_task(task: dict[str, Any]) -> dict[str, Any]:
    """One task's calls, outcome and waste measures."""
    result = task.get("task_result", {})
    calls = []
    for step in task.get("steps", []):
        if step.get("tool") == "finish_investigation":
            continue
        # A composite tool spends several runtime calls; each one counts on its own.
        for reward in step.get("inner_rewards") or []:
            calls.append({**step, "reward": reward, "inner_rewards": None})
        if "reward" in step and not step.get("inner_rewards"):
            calls.append(step)
    hits = [bool((step.get("reward") or 0) > 0) for step in calls]
    last_hit = max((index for index, hit in enumerate(hits) if hit), default=-1)
    streak = longest = 0
    for hit in hits:
        streak = 0 if hit else streak + 1
        longest = max(longest, streak)
    keys = Counter(
        json.dumps(
            {k: v for k, v in (step.get("arguments") or {}).items() if k != "reasoning"},
            sort_keys=True,
        )
        + str(step.get("tool"))
        for step in calls
    )
    category, _ = classify(task)
    return {
        "task": task["task_id"][:8],
        "scenario": scenario(task),
        "category": category,
        "quality": round(float(result.get("quality_score") or 0), 3),
        "efficiency": round(float(result.get("efficiency_score") or 0), 3),
        "calls": len(calls),
        "hits": sum(hits),
        "tail_after_last_hit": len(calls) - 1 - last_hit if calls else 0,
        "longest_miss_streak": longest,
        "repeats": sum(count - 1 for count in keys.values() if count > 1),
        "first_hit_at": next((index + 1 for index, hit in enumerate(hits) if hit), None),
        "sequence": [(call_kind(step), hit) for step, hit in zip(calls, hits, strict=True)],
    }


def main() -> None:
    """Print aggregates and optionally write per-task details as JSON."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("runs", nargs="+")
    parser.add_argument("--root", type=Path, default=Path("runs"))
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    reviews = []
    for prefix in args.runs:
        for run in args.root.iterdir():
            if run.is_dir() and run.name.startswith(prefix):
                for path in sorted(run.glob("*.json")):
                    if path.name != "run.json":
                        reviews.append(
                            {"run": run.name[:8], **review_task(json.loads(path.read_text()))}
                        )
    if not reviews:
        raise SystemExit("no tasks")
    kinds: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for review in reviews:
        for kind, hit in review["sequence"]:
            kinds[kind][0] += 1
            kinds[kind][1] += hit
    n = len(reviews)
    mean = statistics.mean
    print(
        f"tasks={n} calls/task={mean(r['calls'] for r in reviews):.1f} "
        f"hits/task={mean(r['hits'] for r in reviews):.1f} "
        f"tail after last hit={mean(r['tail_after_last_hit'] for r in reviews):.1f} "
        f"longest miss streak={mean(r['longest_miss_streak'] for r in reviews):.1f} "
        f"repeats={mean(r['repeats'] for r in reviews):.2f} "
        f"first hit at call={mean(r['first_hit_at'] or 0 for r in reviews):.1f}"
    )
    print(f"\n{'call kind':42} {'/task':>6} {'hit':>5} {'misses/task':>11}")
    for kind, (count, hit) in sorted(kinds.items(), key=lambda kv: -(kv[1][0] - kv[1][1])):
        if count >= 10:
            print(f"{kind:42} {count / n:6.2f} {hit / count:5.2f} {(count - hit) / n:11.2f}")
    by_scenario: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for review in reviews:
        by_scenario[review["scenario"]].append(review)
    print(f"\n{'scenario':40} {'n':>3} {'q':>5} {'eff':>5} {'calls':>5} {'tail':>5} {'streak':>6}")
    for name, items in sorted(
        by_scenario.items(), key=lambda kv: mean(r["quality"] for r in kv[1])
    ):
        print(
            f"{name[:40]:40} {len(items):3} {mean(r['quality'] for r in items):5.2f} "
            f"{mean(r['efficiency'] for r in items):5.2f} {mean(r['calls'] for r in items):5.1f} "
            f"{mean(r['tail_after_last_hit'] for r in items):5.1f} "
            f"{mean(r['longest_miss_streak'] for r in items):6.1f}"
        )
    if args.json:
        args.json.write_text(json.dumps(reviews, ensure_ascii=False))


if __name__ == "__main__":
    main()
