from bluesec1_agent.casefile import CaseFile
from bluesec1_agent.stacking import key_processes, stable_fragment, summarize_stack


def _process(entity_id: str, cmdline: str, host: str, user: str = "CORP\\svc") -> dict:
    return {
        "kind": "entity",
        "id": entity_id,
        "type": "windows_process",
        "host_id": host,
        "properties": {
            "image_path": "C:\\Windows\\System32\\powershell.exe",
            "cmdline": cmdline,
            "user": user,
            "start_time": f"2024-06-12T0{entity_id[-1]}:00:00+00:00",
        },
    }


def test_stable_fragment_skips_tokens_with_numbers() -> None:
    """Run-specific numbers are left out; the script path identifies the command."""
    properties = {"cmdline": "powershell -File \\\\dc\\NETLOGON\\Collect.ps1 -Run 42"}

    assert stable_fragment(properties) == "\\\\dc\\NETLOGON\\Collect.ps"
    assert stable_fragment({"cmdline": "x 1", "image_path": "C:\\a\\chrome.exe"}) == "chrome.exe"


def test_summary_counts_runs_hosts_and_accounts_of_one_shape() -> None:
    """Same command with other numbers counts; a different command does not."""
    case = CaseFile()
    trigger = _process("p1", "powershell -File Collect.ps1 -Run 1", "h1")
    case.observe(trigger)
    result = {
        "results": [
            trigger,
            _process("p2", "powershell -File Collect.ps1 -Run 2", "h2"),
            _process("p3", "powershell -File Collect.ps1 -Run 3", "h3"),
            _process("p4", "powershell -enc AAAA", "h1", "CORP\\alice"),
        ]
    }

    line = summarize_stack("p1", case, "Collect.ps1", result)

    assert "3 runs of this command shape on 3 host(s) by 1 account(s)" in line
    lone = summarize_stack("p1", case, "Collect.ps1", {"results": [trigger]})
    assert "no other run" in lone


def test_key_processes_start_with_the_trigger() -> None:
    """Only processes are stacked, the alert's own first."""
    case = CaseFile()
    case.observe(
        {
            "results": [
                _process("p1", "a", "h1"),
                {"id": "h1", "type": "host", "properties": {"hostname": "x"}},
            ]
        }
    )

    assert key_processes(case, {"h1", "p1"}) == ["p1"]
