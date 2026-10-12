import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from loguru import logger


class TrajectoryRecorder:
    """Write one JSON file per task so runs can be compared afterwards."""

    def __init__(self, root: Path | None, run_id: str, metadata: dict[str, Any]) -> None:
        """Prepare the run directory.

        Args:
            root: Base directory for trajectories; None disables recording.
            run_id: Remote run identifier.
            metadata: Run-level settings worth keeping next to the results.
        """
        self.directory = root / run_id if root is not None else None
        if self.directory is not None:
            self.directory.mkdir(parents=True, exist_ok=True)
            self._write("run.json", {"run_id": run_id, "started_at": _now(), **metadata})

    def save_task(self, task_id: str, record: dict[str, Any]) -> None:
        """Persist one finished task trajectory.

        Args:
            task_id: Remote task identifier.
            record: Alert, steps and the authoritative task result.
        """
        self._write(f"{task_id}.json", {"task_id": task_id, "saved_at": _now(), **record})

    def _write(self, name: str, payload: dict[str, Any]) -> None:
        """Write JSON without letting disk errors break the run."""
        if self.directory is None:
            return
        try:
            (self.directory / name).write_text(
                json.dumps(payload, ensure_ascii=False, indent=2, default=str),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.warning("Could not write trajectory {}: {}", name, exc)


def _now() -> str:
    """Return the current UTC time in ISO 8601."""
    return datetime.now(UTC).isoformat()
