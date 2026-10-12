"""Compare experiment arms within scenarios.

For each task, the arm is read from the trajectory (a top-level key or a key on the final
step); quality is compared with the mean of the same scenario and verdict in the other
arms, so scenario difficulty cancels out.

Usage:
    uv run python scripts/arm_report.py <arm key> <run prefix> [...] [--verdict benign]
"""

import argparse
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from failure_report import scenario  # noqa: E402


def arm_of(task: dict[str, Any], key: str) -> str | None:
    """The task's arm: a top-level key, else the latest step that records it."""
    if key in task:
        return str(task[key])
    for step in reversed(task.get("steps", [])):
        if key in step:
            return str(step[key])
    return None


def main() -> None:
    """Print per-arm paired differences."""
    parser = argparse.ArgumentParser()
    parser.add_argument("key")
    parser.add_argument("runs", nargs="+")
    parser.add_argument("--verdict")
    parser.add_argument(
        "--score", action="store_true", help="compare q * (0.6 + 0.4 * e), not quality"
    )
    args = parser.parse_args()
    rows = []
    for prefix in args.runs:
        for path in Path("runs").glob(f"{prefix}*/*.json"):
            task = json.loads(path.read_text())
            finals = [s for s in task.get("steps", []) if s.get("tool") == "finish_investigation"]
            if "task_result" not in task or not finals:
                continue
            verdict = (finals[-1].get("arguments", {}).get("submission") or {}).get("verdict")
            if args.verdict and verdict != args.verdict:
                continue
            arm = arm_of(task, args.key)
            if arm is None:
                continue
            result = task["task_result"]
            quality, efficiency = result["quality_score"], result["efficiency_score"]
            value = quality * (0.6 + 0.4 * efficiency) if args.score else quality
            rows.append((scenario(task), verdict, arm, value, efficiency))
    by_cell = defaultdict(list)
    for row in rows:
        by_cell[(row[0], row[1])].append(row)
    diffs = defaultdict(list)
    totals = defaultdict(list)
    for cell in by_cell.values():
        for _scenario, _verdict, arm, quality, efficiency in cell:
            totals[arm].append((quality, efficiency))
            others = [r[3] for r in cell if r[2] != arm]
            if others:
                diffs[arm].append(quality - statistics.mean(others))
    for arm in sorted(totals):
        quality = statistics.mean(q for q, _ in totals[arm])
        efficiency = statistics.mean(e for _, e in totals[arm])
        paired = diffs.get(arm, [])
        mean_diff = f"{statistics.mean(paired):+.3f}" if paired else "  n/a"
        print(
            f"{arm:14} n={len(totals[arm]):3} q={quality:.3f} e={efficiency:.3f} "
            f"within-scenario vs other arms: {mean_diff} (paired n={len(paired)})"
        )


if __name__ == "__main__":
    main()
