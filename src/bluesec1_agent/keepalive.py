"""Keep a task's run open while the agent is only talking to the LLM.

The platform closes a run after 15 minutes without a client request. The decision
phase of a task - chain assessments, a tie-break, report samples - makes no runtime
call, and a slow LLM provider can stretch it past that. A closed run loses every task
left in it, so after a long silence one cheap lookup of an alert entity is made. It
costs one of the task's tool calls and happens only when the LLM is that slow.
"""

import asyncio
import time
from typing import Any

# Well inside the platform's 15 minutes, with its one-minute check interval.
IDLE_SECONDS = 600.0
CHECK_SECONDS = 30.0
PROBE_REASONING = "Keep the run open during a long analysis step."


class KeepAliveSession:
    """A task session that records its last runtime request and can renew it."""

    def __init__(
        self,
        session: Any,
        probe: tuple[str, dict[str, Any]] | None,
        idle_seconds: float = IDLE_SECONDS,
    ) -> None:
        """Wrap a session.

        Args:
            session: The remote task session.
            probe: Tool name and arguments of a harmless lookup, or None to never probe.
            idle_seconds: Silence after which the probe is sent.
        """
        self._session = session
        self._probe = probe
        self._idle_seconds = idle_seconds
        self._lock = asyncio.Lock()
        self.last_request = time.monotonic()
        self.probes = 0

    def __getattr__(self, name: str) -> Any:
        """Everything but tool calls goes to the wrapped session."""
        return getattr(self._session, name)

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        """Call a tool, one at a time, and note the time."""
        async with self._lock:
            try:
                return await self._session.call_tool(tool_name, arguments)
            finally:
                self.last_request = time.monotonic()

    async def keep_alive(self) -> None:
        """Probe the runtime whenever it has been silent for too long; runs until cancelled."""
        while True:
            await asyncio.sleep(CHECK_SECONDS)
            if self._probe is None or time.monotonic() - self.last_request < self._idle_seconds:
                continue
            if self._lock.locked():
                continue
            tool, arguments = self._probe
            try:
                await self.call_tool(tool, arguments)
                self.probes += 1
            except Exception:  # noqa: BLE001 - a failed probe must not end the task
                self.last_request = time.monotonic()
