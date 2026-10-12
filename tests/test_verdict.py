from bluesec1_agent.casefile import CaseFile
from bluesec1_agent.verdict import decide

PROCESS = {
    "id": "p1",
    "type": "windows_process",
    "properties": {
        "image_path": "C:\\Users\\bob\\AppData\\Local\\Temp\\svchost.exe",
        "signer": "Unknown",
    },
}
NONE: dict = {"stages": [], "target_event": "none", "proximity": 0, "signal_explanations": []}


def case_file() -> CaseFile:
    case = CaseFile()
    case.observe(PROCESS)
    return case


def test_unexplained_strong_signal_is_malicious() -> None:
    decision = decide(NONE, case_file())

    assert decision.verdict == "malicious"
    assert decision.unexplained_signals
    assert decision.artifact_candidates(case_file()) == ["p1"]


def test_explanation_needs_cited_fields_with_values() -> None:
    unsupported = {
        "signal": "s",
        "entity_id": "p1",
        "property_fields": ["cmdline"],
        "explanation": "admin",
    }
    supported = {**unsupported, "property_fields": ["signer", "image_path"]}

    rejected = decide({**NONE, "signal_explanations": [unsupported]}, case_file())
    accepted = decide({**NONE, "signal_explanations": [supported]}, case_file())

    assert rejected.verdict == "malicious" and rejected.rejected
    assert accepted.verdict == "benign"
    assert accepted.evidence_candidates()[0]["property_fields"] == ["signer", "image_path"]


def test_stage_without_seen_entities_does_not_count() -> None:
    clean = CaseFile()
    clean.observe({"id": "h1", "type": "host", "properties": {"hostname": "APP1"}})
    invented = {"tactic": "execution", "evidence": "x", "entity_ids": ["made-up"]}
    grounded = {**invented, "entity_ids": ["h1"]}

    assert decide({**NONE, "stages": [invented]}, clean).verdict == "benign"
    assert decide({**NONE, "stages": [grounded]}, clean).verdict == "malicious"


def test_mis_copied_ids_resolve_to_the_known_entity() -> None:
    case = CaseFile()
    case.observe(
        {
            "id": "c860ea70-51cb-59f1-83a0-259e8ec7e6e9",
            "type": "powershell_script",
            "properties": {"script_text": "Get-Service", "path": "C:\\\\ops\\\\inventory.ps1"},
        }
    )
    typo = {
        "signal": "s",
        "entity_id": "c860ea70-51cb-59f4-9807-0d7efd02ff82",
        "property_fields": ["script_text"],
        "explanation": "inventory script",
    }

    decision = decide({**NONE, "signal_explanations": [typo]}, case)

    assert decision.rejected == []
    assert decision.evidence_candidates()[0]["entity_id"] == "c860ea70-51cb-59f1-83a0-259e8ec7e6e9"


def _remote_shell(entity_id: str, cmdline: str) -> dict:
    """A masquerading process whose strong signal needs an explanation."""
    return {
        "id": entity_id,
        "type": "windows_process",
        "properties": {
            "image_path": "C:\\Users\\Public\\svchost.exe",
            "parent_image": "C:\\Windows\\System32\\wsmprovhost.exe",
            "user": "CORP\\pki_ops_svc",
            "cmdline": cmdline,
        },
    }


def test_explanation_covers_exact_repeats_only() -> None:
    """A repeat of the explained behaviour is covered; a different command is not."""
    case = CaseFile()
    case.observe(
        {
            "results": [
                _remote_shell("s1", "svchost.exe -k admin"),
                _remote_shell("s2", "svchost.exe -k admin"),
                _remote_shell("s3", "svchost.exe -enc AAAA"),
            ]
        }
    )
    explanation = {
        "signal": "masquerading",
        "entity_id": "s1",
        "property_fields": ["user", "parent_image"],
        "explanation": "scheduled PKI maintenance",
    }

    decision = decide({**NONE, "signal_explanations": [explanation]}, case)

    unexplained = {signal.split(":", 1)[0] for signal in decision.unexplained_signals}
    assert unexplained == {"s3"}
    assert decision.verdict == "malicious"


def test_unexplained_signal_alone_keeps_a_benign_draft() -> None:
    """Without an attack stage, open doubts do not overturn a benign conclusion."""
    benign = decide(NONE, case_file(), draft_verdict="benign")
    malicious = decide(NONE, case_file(), draft_verdict="malicious")
    staged = decide(
        {**NONE, "stages": [{"tactic": "execution", "entity_ids": ["p1"], "evidence": "x"}]},
        case_file(),
        draft_verdict="benign",
    )

    assert benign.verdict == "benign" and benign.unexplained_signals
    assert malicious.verdict == "malicious"
    assert staged.verdict == "malicious"


def test_relation_fields_can_explain_the_entities_it_links() -> None:
    """A logon's own fields are evidence; the explanation covers both its ends."""
    case = case_file()
    case.observe(
        {
            "id": "r1",
            "type": "logged_on_to",
            "source_id": "u1",
            "target_id": "p1",
            "logon_properties": {"logon_type": "service"},
        }
    )
    explanation = {
        "signal": "masquerading",
        "entity_id": "r1",
        "property_fields": ["logon_type"],
        "explanation": "service logon",
    }

    decision = decide({**NONE, "signal_explanations": [explanation]}, case)

    assert decision.verdict == "benign"
    assert decision.evidence_candidates(case)[0]["anchor"] == "relation"
