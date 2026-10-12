from pathlib import Path

from bluesec1_agent.knowledge import KnowledgeBase, default_knowledge

RECORDS = {
    "detections": [
        {
            "name": "WinRM Spawning a Process",
            "type": "TTP",
            "mitre": ["T1190"],
            "conditions": [
                "parent_process_name = wsmprovhost.exe",
                'process_name IN ("cmd.exe","powershell.exe")',
            ],
            "known_false_positives": "System management software may spawn processes.",
        },
        {
            "name": "Creation of Shadow Copy",
            "type": "TTP",
            "mitre": ["T1003.003"],
            "conditions": [
                "process_name = vssadmin.exe",
                "process = *create*",
                "process = *shadow*",
            ],
            "known_false_positives": "Legitimate administrator usage.",
        },
    ],
    "stories": [{"name": "Ransomware", "narrative": "Encrypts files."}],
}


def test_search_ranks_free_text_questions() -> None:
    knowledge = KnowledgeBase(RECORDS)

    question = "is vssadmin creating a shadow copy a false positive for the admin?"
    assert knowledge.search(question)[0].startswith("Creation of Shadow Copy")
    assert knowledge.search("wsmprovhost spawned powershell")[0].startswith("WinRM")
    assert knowledge.search("kerberos golden ticket forged") == []
    assert knowledge.search("encrypts", kind="stories")


def test_match_process_uses_image_parent_and_command_line() -> None:
    knowledge = KnowledgeBase(RECORDS)
    winrm_child = {
        "image_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "parent_image": "C:\\Windows\\System32\\wsmprovhost.exe",
    }
    shadow = {
        "image_path": "C:\\Windows\\System32\\vssadmin.exe",
        "cmdline": "vssadmin create shadow /for=C:",
    }
    listing = {
        "image_path": "C:\\Windows\\System32\\vssadmin.exe",
        "cmdline": "vssadmin list writers",
    }

    assert knowledge.match_process(winrm_child)[0].startswith("WinRM Spawning a Process")
    assert knowledge.match_process(shadow)[0].startswith("Creation of Shadow Copy")
    assert knowledge.match_process(listing) == []


def test_packaged_knowledge_base_loads() -> None:
    knowledge = default_knowledge()

    assert knowledge is not None
    assert len(knowledge.records["detections"]) > 1000


def test_match_entity_covers_script_blocks_and_registry_keys() -> None:
    knowledge = KnowledgeBase(
        {
            "detections": [
                {
                    "name": "Mimikatz in script block",
                    "type": "TTP",
                    "conditions": ["script_text IN (*sekurlsa::*, *kerberos::golden*)"],
                },
                {
                    "name": "GetCurrent user",
                    "type": "Hunting",
                    "conditions": ['script_text = "*GetCurrent()*"'],
                },
                {
                    "name": "Run key persistence",
                    "type": "TTP",
                    "conditions": ['registry_path = "*\\\\CurrentVersion\\\\Run*"'],
                },
            ],
            "stories": [],
        }
    )

    script = {"script_text": "Invoke-Mimikatz -Command 'sekurlsa::logonpasswords'; GetCurrent()"}
    run_key = {"path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "value_name": "x"}

    assert [m.split(" [")[0] for m in knowledge.match_entity("powershell_script", script)] == [
        "Mimikatz in script block"
    ]
    assert knowledge.match_entity("registry_key", run_key)[0].startswith("Run key persistence")


def test_guides_load_from_markdown_and_match_triggers(tmp_path: Path) -> None:
    from bluesec1_agent.knowledge import load_guides

    header = "---\nname: WinRM\nprocesses: wsmprovhost.exe\nsignals: external address\n---\n"
    (tmp_path / "winrm.md").write_text(header + "Check the source.\n", encoding="utf-8")
    knowledge = KnowledgeBase({"detections": [], "stories": [], "guides": load_guides(tmp_path)})

    process = {"image_path": "C:\\Windows\\System32\\wsmprovhost.exe"}
    external = ["suspicious: connection to external address 1.2.3.4:443"]
    assert knowledge.match_guides("windows_process", process, []) == ["winrm"]
    assert knowledge.match_guides("network_connection", {}, external) == ["winrm"]
    assert knowledge.match_guides("windows_file", {}, []) == []
    assert (knowledge.guide("winrm") or "").startswith("# WinRM\nCheck the source.")


def test_packaged_guides_cover_the_main_case_types() -> None:
    knowledge = default_knowledge()

    assert knowledge is not None
    stems = {guide["stem"] for guide in knowledge.records["guides"]}
    assert {"winrm", "windows-update", "external-endpoint", "legitimacy-evidence"} <= stems


def test_shipped_type_guides_match_only_their_triggers() -> None:
    """Alert-type guides attach to the alert's own process, and parents narrow them."""
    from bluesec1_agent.knowledge import default_knowledge

    kb = default_knowledge()
    scheduled = {
        "image_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "parent_image": "C:\\Windows\\System32\\svchost.exe",
    }
    from_word = {**scheduled, "parent_image": "C:\\Program Files\\Office\\WINWORD.EXE"}
    edr = {"image_path": "C:\\Program Files\\ESET\\ESET Security\\ekrn.exe"}

    assert "scheduled-script" in kb.match_guides("windows_process", scheduled, [])
    assert "scheduled-script" not in kb.match_guides("windows_process", from_word, [])
    assert "security-product" in kb.match_guides("windows_process", edr, [])
    assert "security-product" not in kb.match_guides("windows_process", edr, [], is_trigger=False)


def test_triage_playbook_comes_with_every_alert_only() -> None:
    """The general triage playbook is offered for any trigger, never mid-investigation."""
    from bluesec1_agent.knowledge import default_knowledge

    kb = default_knowledge()
    anything = {"image_path": "C:\\Windows\\System32\\notepad.exe"}
    kernel = {"image_path": "System"}

    assert "triage" in kb.match_guides("windows_process", anything, [])
    assert "triage" not in kb.match_guides("windows_process", anything, [], is_trigger=False)
    assert "system-kernel" in kb.match_guides("windows_process", kernel, [])
