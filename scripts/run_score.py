"""Leaderboard-style score of practice runs: the sum over tasks of q * (0.6 + 0.4 * e).

Usage:
    uv run python scripts/run_score.py <run prefix> [...]
"""

import json
import sys
from pathlib import Path


def main() -> None:
    """Print each run's score, mean quality, efficiency and task count."""
    for prefix in sys.argv[1:]:
        for run in sorted(Path("runs").glob(f"{prefix}*")):
            results = []
            for path in run.glob("*.json"):
                task = json.loads(path.read_text())
                if "task_result" in task:
                    results.append(task["task_result"])
            if not results:
                continue
            score = sum(
                float(r.get("quality_score") or 0)
                * (0.6 + 0.4 * float(r.get("efficiency_score") or 0))
                for r in results
            )
            quality = sum(float(r.get("quality_score") or 0) for r in results) / len(results)
            efficiency = sum(float(r.get("efficiency_score") or 0) for r in results) / len(results)
            print(
                f"{run.name[:8]} tasks={len(results):2} score={score:6.2f} "
                f"per_task={score / len(results):.3f} q={quality:.3f} e={efficiency:.3f}"
            )


if __name__ == "__main__":
    main()
