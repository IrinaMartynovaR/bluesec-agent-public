import asyncio
from typing import Any

from bluesec1_agent import keepalive
from bluesec1_agent.keepalive import KeepAliveSession


class Recorder:
    """Session stand-in that records tool calls."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.task_id = "task-1"

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> str:
        self.calls.append(tool_name)
        return "ok"


def test_probe_is_sent_only_after_a_long_silence(monkeypatch: Any) -> None:
    """A silent task gets a probe; attributes still reach the wrapped session."""
    monkeypatch.setattr(keepalive, "CHECK_SECONDS", 0.01)
    inner = Recorder()
    guarded = KeepAliveSession(inner, ("get_entity", {"entity_id": "e1"}), idle_seconds=0.05)

    async def scenario() -> None:
        keeper = asyncio.create_task(guarded.keep_alive())
        await guarded.call_tool("search", {})
        assert guarded.probes == 0
        for _ in range(200):
            if guarded.probes:
                break
            await asyncio.sleep(0.01)
        keeper.cancel()

    asyncio.run(scenario())

    assert inner.calls[0] == "search"
    assert guarded.probes >= 1 and "get_entity" in inner.calls
    assert guarded.task_id == "task-1"
