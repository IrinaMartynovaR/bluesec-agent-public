from bluesec1_agent.casefile import CaseFile
from bluesec1_agent.models import ToolCatalog, ToolSpec
from bluesec1_agent.report_form import LEGITIMACY_FORM_TOOL, build_benign_report


def _case() -> CaseFile:
    case = CaseFile()
    case.observe(
        {
            "results": [
                {
                    "id": "p1",
                    "type": "windows_process",
                    "properties": {"image_path": "C:\\x.exe", "signer": "Microsoft", "cwd": "C:\\"},
                },
                {"id": "u1", "type": "windows_user", "properties": {"username": "svc"}},
                {"id": "t1", "type": "scheduled_task", "properties": {"task_name": "Sync"}},
            ]
        }
    )
    return case


def test_form_becomes_entity_evidence_with_few_seen_fields() -> None:
    """Answers turn into entity anchors; unknown ids and empty fields are dropped."""
    form = {
        "trigger": {"entity_id": "p1", "fields": ["image_path", "signer", "pid"], "why": "genuine"},
        "account": {"entity_id": "u1", "fields": ["username"], "why": "service account"},
        "purpose": {"entity_id": "t1", "fields": ["task_name"], "why": "inventory task"},
        "initiator": {"entity_id": "nope", "fields": ["x"], "why": "unknown entity"},
        "signal_answers": [
            {"signal": "s", "entity_id": "p1", "fields": ["cwd"], "why": "same process"}
        ],
    }

    report = build_benign_report(form, _case())

    assert report is not None
    evidence = report["submission"]["legitimacy_evidence"]
    assert evidence == [
        {"anchor": "entity", "entity_id": "p1", "property_fields": ["image_path", "signer", "cwd"]},
        {"anchor": "entity", "entity_id": "u1", "property_fields": ["username"]},
        {"anchor": "entity", "entity_id": "t1", "property_fields": ["task_name"]},
    ]
    assert "account: service account" in report["submission"]["reasoning"]


def test_form_with_nothing_seen_builds_no_report() -> None:
    """A form naming no seen entity gives the caller nothing to submit."""
    form = {"trigger": {"entity_id": "ghost", "fields": ["image_path"], "why": "made up"}}

    assert build_benign_report(form, _case()) is None


def test_form_schema_is_a_valid_tool() -> None:
    """The form validates as a tool the model can be forced to call."""
    catalog = ToolCatalog([ToolSpec.model_validate(LEGITIMACY_FORM_TOOL)])
    arguments = {"trigger": {"entity_id": "p1", "fields": ["a", "b", "c", "d"], "why": "x" * 5}}

    _, error = catalog.validate("legitimacy_form", arguments)

    assert error is not None and "fields" in error


def test_roles_lead_and_checked_explanations_fill_only_a_bare_report() -> None:
    """Form roles come first; a checked explanation is added only to a trigger-only form."""
    signal = {"anchor": "relation", "relation_id": "r9", "property_fields": ["logon_type"]}
    bare = {"trigger": {"entity_id": "p1", "fields": ["image_path"], "why": "genuine binary"}}
    full = {
        **bare,
        "account": {"entity_id": "u1", "fields": ["username"], "why": "service account"},
    }

    bare_report = build_benign_report(bare, _case(), [signal])
    full_report = build_benign_report(full, _case(), [signal])

    assert bare_report is not None and full_report is not None
    assert bare_report["submission"]["legitimacy_evidence"][1] == signal
    assert [item.get("entity_id") for item in full_report["submission"]["legitimacy_evidence"]] == [
        "p1",
        "u1",
    ]


def test_builtin_account_is_not_reported() -> None:
    """SYSTEM proves nothing about authorization, so the account role drops it."""
    case = _case()
    case.observe(
        {
            "id": "sys",
            "type": "windows_user",
            "properties": {"username": "SYSTEM", "sid": "S-1-5-18"},
        }
    )
    form = {
        "trigger": {"entity_id": "p1", "fields": ["image_path"], "why": "genuine binary"},
        "account": {"entity_id": "sys", "fields": ["username"], "why": "runs as system"},
    }

    report = build_benign_report(form, case)

    assert report is not None
    assert [item["entity_id"] for item in report["submission"]["legitimacy_evidence"]] == ["p1"]
