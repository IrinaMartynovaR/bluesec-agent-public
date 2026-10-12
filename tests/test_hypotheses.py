from test_agent import FINISH, FakeActionClient, FakeSession, get_entity, run_agent

from bluesec1_agent.hypotheses import HypothesisBoard
from bluesec1_agent.models import AgentAction


def test_resolved_hypothesis_needs_seen_evidence() -> None:
    """Supported or refuted needs ids from the case; otherwise it stays open."""
    board = HypothesisBoard()

    feedback = board.update(
        [
            {"id": "H1", "statement": "admin session", "status": "supported", "evidence_ids": []},
            {
                "id": "H2",
                "statement": "attacker shell",
                "status": "refuted",
                "evidence_ids": ["e1"],
            },
        ],
        {"e1"},
    )

    assert board.open() == ["H1"]
    assert "H1" in feedback["refused"][0]
    assert board.render()[1] == "H2 [refuted] attacker shell evidence=e1"


def test_open_hypotheses_hold_the_report_once() -> None:
    """The first report with an open hypothesis is returned; the second goes through."""
    record = AgentAction(
        tool="hypotheses",
        arguments={
            "items": [{"id": "H1", "statement": "macro next to the alert", "status": "open"}]
        },
    )
    llm = FakeActionClient([record, get_entity("entity-1"), FINISH, FINISH])
    session = FakeSession()

    run_agent(llm, session, hypotheses=True, trajectory_dir=None)

    assert [name for name, _ in session.calls] == ["get_entity", "finish_investigation"]
    held = llm.requests[3][-1]["content"]
    assert "still open" in held and "macro next to the alert" in held
