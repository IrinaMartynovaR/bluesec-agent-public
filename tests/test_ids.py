import json

from bluesec1_agent.ids import IdRegistry

HOST = "11111111-1111-5111-8111-111111111111"
PROCESS = "22222222-2222-5222-8222-222222222222"
RELATION = "33333333-3333-5333-8333-333333333333"
AD_OBJECT = "44444444-4444-5444-8444-444444444444"
UNSEEN = "55555555-5555-5555-8555-555555555555"

ALERT = {
    "trigger_entities": [
        {"id": HOST, "type": "host", "properties": {"ad_object_id": AD_OBJECT}},
        {"id": PROCESS, "type": "windows_process", "properties": {}, "host_id": HOST},
    ],
}


def registry() -> IdRegistry:
    """Build a registry that has seen the alert and one entity lookup."""
    ids = IdRegistry()
    ids.observe(ALERT)
    entity = {"id": PROCESS, "properties": {}, "relation_ids": {"incoming": [RELATION]}}
    ids.observe(json.dumps(entity))
    return ids


def test_registry_accepts_ids_in_their_own_role() -> None:
    ids = registry()

    assert ids.check({"entity_id": PROCESS, "reasoning": "x"}) is None
    assert ids.check({"relation_id": RELATION}) is None
    assert ids.check({"ad_object_id": AD_OBJECT}) is None


def test_registry_rejects_ids_of_another_role() -> None:
    ids = registry()

    assert "relation id" in (ids.check({"entity_id": RELATION}) or "")
    assert "entity id" in (ids.check({"ad_object_id": PROCESS}) or "")
    # AD objects are entities too, so they may be reported where an entity is expected.
    assert ids.check({"entity_id": AD_OBJECT}) is None


def test_registry_rejects_unseen_ids_even_when_nested() -> None:
    ids = registry()
    submission = {"submission": {"ir_artifacts": [{"entity_id": UNSEEN, "kind": "other"}]}}

    assert "never appeared" in (ids.check(submission) or "")


def test_empty_registry_accepts_any_id() -> None:
    assert IdRegistry().check({"entity_id": "process-1"}) is None


def test_registry_suggests_the_id_the_model_mistyped() -> None:
    ids = registry()
    typo = PROCESS[:9] + PROCESS[14:]

    problem = ids.check({"entity_id": typo}) or ""
    assert "never appeared" in problem and PROCESS in problem


def test_registry_checks_ids_of_any_format() -> None:
    ids = IdRegistry()
    ids.observe({"id": "host:APP1", "properties": {}})

    assert ids.check({"entity_id": "host:APP1"}) is None
    assert ids.check({"entity_id": "host:APP2"})
