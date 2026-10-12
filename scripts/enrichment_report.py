"""Where the agent under-collects evidence or over-reports, per scenario.

The final report's reward is about 9 points per evidence object times the task score
(the organizers' worked example: 45 = 9 x 5 objects at score 1), so the expected
evidence count is |E| ~ final_reward / (9 * score). Evidence found = the two alert
objects plus the rewards of calls that opened evidence. Comparing found with |E| shows
under-collection; comparing report items with found shows over-reporting.

Usage:
    uv run python scripts/enrichment_report.py <run prefix> [...]
"""

import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from failure_report import scenario  # noqa: E402

RUNTIME = {"search", "get_entity", "get_relation", "get_ad_object_info"}
ALERT_OBJECTS = 2
PER_OBJECT = 9.0


def task_row(task: dict[str, Any]) -> dict[str, Any] | None:
    """Expected and found evidence, report size and quality of one task."""
    result = task.get("task_result") or {}
    finals = [s for s in task.get("steps", []) if s.get("tool") == "finish_investigation"]
    if not finals or not result:
        return None
    quality, efficiency = result["quality_score"], result["efficiency_score"]
    score = quality * (0.6 + 0.4 * efficiency)
    step_reward = 0.0
    for step in task["steps"]:
        if step.get("tool") == "finish_investigation":
            continue
        if step.get("inner_rewards") is not None:
            step_reward += sum(step["inner_rewards"])
        elif step.get("reward") is not None:
            step_reward += float(step["reward"])
    final = result["total_reward"] - step_reward
    submission = finals[-1]["arguments"]["submission"]
    items = submission.get("ir_artifacts") or submission.get("legitimacy_evidence") or []
    return {
        "scenario": scenario(task),
        "verdict": submission.get("verdict"),
        "quality": quality,
        "expected": final / (PER_OBJECT * score) if score > 0.05 else None,
        "found": ALERT_OBJECTS + step_reward,
        "items": len(items),
        "calls": result["tool_calls"],
    }


def main() -> None:
    """Print per-scenario enrichment and report size."""
    rows = []
    for prefix in sys.argv[1:]:
        for path in Path("runs").glob(f"{prefix}*/*.json"):
            row = task_row(json.loads(path.read_text()))
            if row is not None:
                rows.append(row)
    cells = defaultdict(list)
    for row in rows:
        cells[(row["scenario"], row["verdict"])].append(row)
    print(
        f"{'scenario':34} {'verd':4} {'n':>3} {'q':>5} {'|E|':>5} {'found':>5} "
        f"{'cover':>5} {'items':>5} {'calls':>5} {'loss':>5}"
    )
    lines = []
    for (name, verdict), cell in cells.items():
        expected = [r["expected"] for r in cell if r["expected"]]
        if not expected:
            continue
        size = statistics.median(expected)
        found = statistics.mean(r["found"] for r in cell)
        loss = sum(1 - r["quality"] for r in cell) / len({p for p in sys.argv[1:]})
        lines.append(
            (
                loss,
                name,
                verdict,
                len(cell),
                statistics.mean(r["quality"] for r in cell),
                size,
                found,
                found / size,
                statistics.mean(r["items"] for r in cell),
                statistics.mean(r["calls"] for r in cell),
            )
        )
    for loss, name, verdict, n, q, size, found, cover, items, calls in sorted(lines, reverse=True):
        print(
            f"{name[:34]:34} {str(verdict)[:4]:4} {n:3} {q:5.2f} {size:5.1f} {found:5.1f} "
            f"{cover:5.2f} {items:5.1f} {calls:5.1f} {loss:5.2f}"
        )


if __name__ == "__main__":
    main()
