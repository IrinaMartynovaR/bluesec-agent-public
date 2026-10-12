from bluesec1_agent.casefile import CaseFile
from bluesec1_agent.report_check import (
    MAX_LEGITIMACY_EVIDENCE,
    check_submission,
    filter_artifacts,
    shape_benign_report,
    vote_reports,
)

HOST = {"id": "h1", "type": "host", "properties": {"hostname": "APP1"}}
PROCESS = {"id": "p1", "type": "windows_process", "properties": {"image_path": "C:\\x.exe"}}


def case_file() -> CaseFile:
    case = CaseFile()
    case.observe([HOST, PROCESS])
    return case


def test_rejects_kind_that_does_not_fit_entity_type() -> None:
    report = {
        "submission": {
            "verdict": "malicious",
            "ir_artifacts": [{"entity_id": "p1", "kind": "host_to_isolate"}],
        }
    }

    assert "windows_process" in (check_submission(report, case_file()) or "")


def test_rejects_benign_evidence_citing_empty_fields() -> None:
    report = {
        "submission": {
            "verdict": "benign",
            "legitimacy_evidence": [
                {"anchor": "entity", "entity_id": "p1", "property_fields": ["signer"]}
            ],
        }
    }

    problem = check_submission(report, case_file()) or ""
    assert "signer" in problem and "image_path" in problem


def test_accepts_consistent_report() -> None:
    report = {
        "submission": {
            "verdict": "malicious",
            "ir_artifacts": [
                {"entity_id": "h1", "kind": "host_to_isolate"},
                {"entity_id": "p1", "kind": "process_observed"},
                {"entity_id": "unknown", "kind": "other"},
            ],
        }
    }

    assert check_submission(report, case_file()) is None


def test_filter_keeps_core_and_chain_artifacts_only() -> None:

    case = case_file()
    case.observe(
        {"id": "c1", "type": "network_connection", "properties": {"dst_ip": "203.0.113.5"}}
    )
    case.observe({"id": "c2", "type": "network_connection", "properties": {"dst_ip": "10.0.0.5"}})
    case.observe({"id": "f1", "type": "windows_file", "properties": {"path": "C:\\data\\a.docx"}})
    report = {
        "submission": {
            "verdict": "malicious",
            "ir_artifacts": [
                {"entity_id": "h1", "kind": "host_to_isolate"},
                {"entity_id": "p1", "kind": "process_observed"},
                {"entity_id": "f1", "kind": "file_observed"},
                {"entity_id": "c1", "kind": "network_block"},
                {"entity_id": "c2", "kind": "network_block"},
            ],
        }
    }

    filtered, dropped = filter_artifacts(report, {"p1"}, case)

    kept = [(a["entity_id"], a["kind"]) for a in filtered["submission"]["ir_artifacts"]]
    assert kept == [("h1", "host_to_isolate"), ("p1", "process_observed"), ("c1", "network_block")]
    assert {a["entity_id"] for a in dropped} == {"f1", "c2"}


def test_filter_keeps_the_first_legitimacy_facts() -> None:
    """A long benign report is cut to its leading, decisive facts."""
    evidence = [
        {"anchor": "entity", "entity_id": f"e{index}", "property_fields": ["path"]}
        for index in range(10)
    ]
    arguments = {"submission": {"verdict": "benign", "legitimacy_evidence": evidence}}

    filtered, dropped = filter_artifacts(arguments, set(), CaseFile())

    assert filtered["submission"]["legitimacy_evidence"] == evidence[:MAX_LEGITIMACY_EVIDENCE]
    assert dropped == evidence[MAX_LEGITIMACY_EVIDENCE:]


def test_filter_drops_catch_all_kinds_even_in_the_chain() -> None:
    """`other` and `cleanup_to_verify` name no response action and never stay."""
    case = CaseFile()
    case.observe({"results": [HOST, PROCESS]})
    artifacts = [
        {"entity_id": "h1", "kind": "host_to_isolate"},
        {"entity_id": "p1", "kind": "process_observed"},
        {"entity_id": "p1", "kind": "other"},
        {"entity_id": "h1", "kind": "cleanup_to_verify"},
    ]
    report = {"submission": {"verdict": "malicious", "ir_artifacts": artifacts}}

    filtered, dropped = filter_artifacts(report, {"p1"}, case)

    assert filtered["submission"]["ir_artifacts"] == artifacts[:2]
    assert dropped == artifacts[2:]


def _malicious(*artifacts: tuple[str, str]) -> dict:
    return {
        "submission": {
            "verdict": "malicious",
            "ir_artifacts": [{"entity_id": e, "kind": k} for e, k in artifacts],
            "reasoning": "r",
        }
    }


def test_vote_keeps_majority_artifacts_and_any_core_one() -> None:
    """A whim of one sample goes; agreed artifacts and every named host stay."""
    reports = [
        _malicious(("h1", "host_to_isolate"), ("p1", "process_observed"), ("f1", "file_observed")),
        _malicious(("p1", "process_observed"), ("h2", "host_to_isolate")),
        _malicious(("h1", "host_to_isolate"), ("p1", "process_observed")),
    ]

    merged, votes = vote_reports(reports, "malicious")

    kept = [(a["entity_id"], a["kind"]) for a in merged["submission"]["ir_artifacts"]]
    assert kept == [
        ("h1", "host_to_isolate"),
        ("p1", "process_observed"),
        ("h2", "host_to_isolate"),
    ]
    assert votes == {"samples": 3, "kept": 3, "candidates": 4}


def test_vote_ignores_reports_with_another_verdict() -> None:
    """Only reports that agree with the derived verdict take part."""
    benign = {"submission": {"verdict": "benign", "legitimacy_evidence": []}}
    single = _malicious(("p1", "process_observed"))

    merged, votes = vote_reports([benign, single, benign], "malicious")

    assert merged == single and votes == {"samples": 1}


def test_vote_keeps_agreed_legitimacy_facts_and_fields() -> None:
    """Benign facts stay when most reports cite the anchor, with the agreed fields."""

    def report(*items: tuple[str, list[str]]) -> dict:
        return {
            "submission": {
                "verdict": "benign",
                "legitimacy_evidence": [
                    {"anchor": "entity", "entity_id": e, "property_fields": f} for e, f in items
                ],
            }
        }

    reports = [
        report(("p1", ["image_path", "signer", "cwd"]), ("u1", ["username"])),
        report(("p1", ["image_path", "signer"]), ("x9", ["path"])),
        report(("p1", ["signer", "image_path"]), ("u1", ["username", "sid"])),
    ]

    merged, _ = vote_reports(reports, "benign")

    evidence = merged["submission"]["legitimacy_evidence"]
    assert [(e["entity_id"], e["property_fields"]) for e in evidence] == [
        ("p1", ["image_path", "signer"]),
        ("u1", ["username"]),
    ]


def test_benign_cap_puts_the_trigger_first() -> None:
    """The default cap keeps three items with the alert's entity leading."""
    evidence = [
        {"anchor": "entity", "entity_id": f"e{index}", "property_fields": ["path"]}
        for index in range(5)
    ]
    arguments = {"submission": {"verdict": "benign", "legitimacy_evidence": evidence}}

    filtered, dropped = filter_artifacts(arguments, set(), CaseFile(), {"e4"})

    kept = [item["entity_id"] for item in filtered["submission"]["legitimacy_evidence"]]
    assert kept == ["e4", "e0", "e1"] and len(dropped) == 2
    untouched, _ = filter_artifacts(arguments, set(), CaseFile(), {"e4"}, benign_cap=None)
    assert untouched is arguments


def test_filter_keeps_blocking_an_external_host() -> None:
    """An attacker's external host is a valid network block, not chain noise."""
    case = CaseFile()
    case.observe(
        {
            "results": [
                HOST,
                PROCESS,
                {
                    "id": "c2",
                    "type": "host",
                    "properties": {
                        "hostname": "BROKER02",
                        "ip": "198.51.100.152",
                        "role": "external",
                    },
                },
                {"id": "lan", "type": "host", "properties": {"hostname": "FS1", "ip": "10.0.0.5"}},
            ]
        }
    )
    artifacts = [
        {"entity_id": "p1", "kind": "process_observed"},
        {"entity_id": "c2", "kind": "network_block"},
        {"entity_id": "lan", "kind": "network_block"},
    ]
    report = {"submission": {"verdict": "malicious", "ir_artifacts": artifacts}}

    filtered, dropped = filter_artifacts(report, {"p1"}, case)

    assert filtered["submission"]["ir_artifacts"] == artifacts[:2]
    assert dropped == artifacts[2:]


def _identity_case() -> CaseFile:
    case_file = CaseFile()
    case_file.observe(
        [
            {
                "id": "t",
                "type": "windows_process",
                "properties": {"image_path": "mmc.exe", "user": "CORP\\adm_j.doe"},
            },
            {"id": "h", "type": "host", "properties": {"hostname": "WS1", "role": "workstation"}},
            {
                "id": "u",
                "type": "windows_user",
                "properties": {
                    "username": "adm_j.doe",
                    "group_memberships": ["Admins"],
                    "account_type": "domain",
                },
            },
            {"id": "x", "type": "windows_process", "properties": {"image_path": "a.exe"}},
        ]
    )
    return case_file


def test_filter_drops_any_artifact_on_powershell_log_records() -> None:
    case_file = CaseFile()
    case_file.observe(
        [
            {"id": "p", "type": "windows_process", "properties": {"image_path": "a.exe"}},
            {
                "id": "c",
                "type": "powershell_cmdlet_invocation",
                "properties": {"command_name": "Set-WmiInstance"},
            },
        ]
    )
    report = {
        "submission": {
            "verdict": "malicious",
            "ir_artifacts": [
                {"entity_id": "p", "kind": "process_observed"},
                {"entity_id": "c", "kind": "persistence_to_remove"},
            ],
        }
    }

    filtered, dropped = filter_artifacts(report, {"p", "c"}, case_file)

    assert [a["entity_id"] for a in filtered["submission"]["ir_artifacts"]] == ["p"]
    assert dropped == [{"entity_id": "c", "kind": "persistence_to_remove"}]


def test_identity_to_rotate_accepts_application_accounts() -> None:
    case_file = CaseFile()
    case_file.observe(
        [
            {"id": "h", "type": "host", "properties": {"hostname": "WEB1"}},
            {"id": "a", "type": "app_account", "properties": {"name": "portal_app"}},
        ]
    )
    report = {
        "submission": {
            "verdict": "malicious",
            "ir_artifacts": [
                {"entity_id": "h", "kind": "host_to_isolate"},
                {"entity_id": "a", "kind": "identity_to_rotate"},
            ],
            "reasoning": "x",
        }
    }

    assert check_submission(report, case_file, "malicious") is None


def test_file_kinds_on_a_process_point_at_its_image_file() -> None:
    from bluesec1_agent.report_check import retarget_file_artifacts

    case_file = CaseFile()
    case_file.observe(
        [
            {
                "id": "p",
                "type": "windows_process",
                "host_id": "h",
                "properties": {"image_path": "C:\\ProgramData\\helper.exe"},
            },
            {
                "id": "f",
                "type": "windows_file",
                "host_id": "h",
                "properties": {"path": "C:\\ProgramData\\helper.exe"},
            },
            {
                "id": "q",
                "type": "windows_process",
                "host_id": "h",
                "properties": {"image_path": "C:\\x\\unseen.exe"},
            },
        ]
    )
    report = {
        "submission": {
            "verdict": "malicious",
            "ir_artifacts": [
                {"entity_id": "p", "kind": "process_observed"},
                {"entity_id": "p", "kind": "file_to_delete"},
                {"entity_id": "q", "kind": "file_to_delete"},
            ],
        }
    }

    fixed, replaced = retarget_file_artifacts(report, case_file)

    assert replaced == ["p"]
    assert fixed["submission"]["ir_artifacts"] == [
        {"entity_id": "p", "kind": "process_observed"},
        {"entity_id": "f", "kind": "file_to_delete"},
        {"entity_id": "q", "kind": "file_to_delete"},
    ]


def _benign_report(*ids: str) -> dict:
    return {
        "submission": {
            "verdict": "benign",
            "legitimacy_evidence": [
                {"anchor": "entity", "entity_id": entity_id, "property_fields": ["image_path"]}
                for entity_id in ids
            ],
        }
    }


def _ids(arguments: dict) -> list[str]:
    return [item["entity_id"] for item in arguments["submission"]["legitimacy_evidence"]]


def test_core_people_keeps_trigger_account_and_other_people() -> None:
    case_file = _identity_case()
    case_file.observe(
        [
            {
                "id": "v",
                "type": "windows_user",
                "properties": {"username": "j.doe", "account_type": "domain"},
            },
            {
                "id": "w",
                "type": "windows_user",
                "properties": {"username": "k.lee", "account_type": "domain"},
            },
            {
                "id": "z",
                "type": "windows_user",
                "properties": {"username": "m.ray", "account_type": "domain"},
            },
            {
                "id": "l",
                "type": "windows_user",
                "properties": {"username": "Administrator", "account_type": "local"},
            },
            {
                "id": "s",
                "type": "windows_user",
                "properties": {"username": "SYSTEM", "sid": "S-1-5-18", "account_type": "domain"},
            },
        ]
    )

    shaped, added = shape_benign_report(
        _benign_report("x", "t", "w"), case_file, {"t", "h"}, "core_people"
    )

    # The trigger first, its account, then up to two other people, the cited one first;
    # the process, local and built-in accounts are dropped.
    assert _ids(shaped)[:3] == ["t", "u", "w"]
    assert len(_ids(shaped)) == 4 and _ids(shaped)[3] in {"v", "z"}
    assert "u" in added and "w" not in added


def test_core_keeps_only_one_other_cited_person() -> None:
    case_file = _identity_case()
    case_file.observe(
        [
            {
                "id": "v",
                "type": "windows_user",
                "properties": {"username": "j.doe", "account_type": "domain"},
            },
            {
                "id": "l",
                "type": "windows_user",
                "properties": {"username": "Administrator", "account_type": "local"},
            },
        ]
    )

    shaped, _ = shape_benign_report(
        _benign_report("t", "l", "x", "v"), case_file, {"t", "h"}, "core"
    )

    assert _ids(shaped) == ["t", "u", "v"]


def test_shape_adds_the_trigger_when_the_model_left_it_out() -> None:
    shaped, added = shape_benign_report(
        _benign_report("x"), _identity_case(), {"t", "h"}, "core_people"
    )

    assert _ids(shaped) == ["t", "u"]
    assert shaped["submission"]["legitimacy_evidence"][0]["property_fields"] == [
        "image_path",
        "user",
    ]
    assert added == ["t", "u"]


def test_shape_leaves_model_reports_and_malicious_verdicts_alone() -> None:
    report = _benign_report("t", "x")
    malicious = {"submission": {"verdict": "malicious", "ir_artifacts": []}}

    assert shape_benign_report(report, _identity_case(), {"t", "h"}, "model") == (report, [])
    assert shape_benign_report(malicious, _identity_case(), {"t", "h"}, "core_people") == (
        malicious,
        [],
    )


def test_shape_skips_a_builtin_trigger_account() -> None:
    case_file = _identity_case()
    case_file.entities["t"]["properties"].update(user="NT AUTHORITY\\SYSTEM", user_sid="S-1-5-18")

    shaped, _ = shape_benign_report(_benign_report("t", "x"), case_file, {"t", "h"}, "core_people")

    assert _ids(shaped)[0] == "t" and "x" not in _ids(shaped)


def test_retarget_skips_system_binaries_other_hosts_and_keeps_both_kinds() -> None:
    from bluesec1_agent.report_check import retarget_file_artifacts

    case_file = CaseFile()
    case_file.observe(
        [
            {
                "id": "ps",
                "type": "windows_process",
                "host_id": "h",
                "properties": {"image_path": "C:\\Windows\\System32\\powershell.exe"},
            },
            {
                "id": "psf",
                "type": "windows_file",
                "host_id": "h",
                "properties": {"path": "C:\\Windows\\System32\\powershell.exe"},
            },
            {
                "id": "p",
                "type": "windows_process",
                "host_id": "h",
                "properties": {"image_path": "C:\\Temp\\evil.exe"},
            },
            {
                "id": "f",
                "type": "windows_file",
                "host_id": "h",
                "properties": {"path": "C:\\Temp\\evil.exe"},
            },
            {
                "id": "q",
                "type": "windows_process",
                "host_id": "h",
                "properties": {"image_path": "C:\\Temp\\other.exe"},
            },
            {
                "id": "g",
                "type": "windows_file",
                "host_id": "elsewhere",
                "properties": {"path": "C:\\Temp\\other.exe"},
            },
        ]
    )
    report = {
        "submission": {
            "verdict": "malicious",
            "ir_artifacts": [
                {"entity_id": "ps", "kind": "file_to_delete"},
                {"entity_id": "f", "kind": "file_observed"},
                {"entity_id": "p", "kind": "file_to_delete"},
                {"entity_id": "q", "kind": "file_to_delete"},
            ],
        }
    }

    fixed, replaced = retarget_file_artifacts(report, case_file)

    assert replaced == ["p"]
    assert fixed["submission"]["ir_artifacts"] == [
        {"entity_id": "ps", "kind": "file_to_delete"},
        {"entity_id": "f", "kind": "file_observed"},
        {"entity_id": "f", "kind": "file_to_delete"},
        {"entity_id": "q", "kind": "file_to_delete"},
    ]


def test_shape_keeps_the_trigger_process_when_the_host_is_cited_first() -> None:
    report = {
        "submission": {
            "verdict": "benign",
            "legitimacy_evidence": [
                {"anchor": "entity", "entity_id": "h", "property_fields": ["hostname"]},
                {"anchor": "entity", "entity_id": "t", "property_fields": ["image_path"]},
            ],
        }
    }

    shaped, _ = shape_benign_report(report, _identity_case(), {"t", "h"}, "core_people")

    assert _ids(shaped) == ["t", "u"]
