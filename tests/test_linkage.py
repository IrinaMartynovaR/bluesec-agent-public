from bluesec1_agent.casefile import CaseFile
from bluesec1_agent.linkage import linked_entities


def test_ties_rank_shared_values_on_the_same_host_first() -> None:
    """The script named by the alert's command line leads; host-only ties come last."""
    case = CaseFile()
    case.observe(
        {
            "results": [
                {
                    "id": "trigger",
                    "type": "windows_process",
                    "host_id": "h1",
                    "properties": {
                        "image_path": "C:\\Windows\\System32\\powershell.exe",
                        "cmdline": 'powershell.exe -File "\\\\corp\\NETLOGON\\Collect.ps1"',
                        "parent_image": "C:\\Windows\\System32\\svchost.exe",
                        "logon_id": "0xc0914",
                    },
                },
                {
                    "id": "script",
                    "type": "powershell_script",
                    "host_id": "h1",
                    "properties": {"path": "\\\\corp\\NETLOGON\\Collect.ps1"},
                },
                {
                    "id": "other_script",
                    "type": "powershell_script",
                    "host_id": "h2",
                    "properties": {"path": "\\\\corp\\NETLOGON\\Collect.ps1"},
                },
                {
                    "id": "service_host",
                    "type": "windows_process",
                    "host_id": "h1",
                    "properties": {"image_path": "C:\\Windows\\System32\\svchost.exe"},
                },
                {
                    "id": "sibling",
                    "type": "windows_process",
                    "host_id": "h1",
                    "properties": {"image_path": "C:\\x.exe", "logon_id": "0xC0914"},
                },
            ]
        }
    )

    lines = linked_entities(case, {"trigger", "h1"})

    order = [line.split(" ", 1)[0] for line in lines]
    assert order == ["script", "other_script", "sibling", "service_host"]
    assert "other host" in lines[1] and "same session" in lines[2] and "same host" in lines[3]


def test_session_ties_need_the_same_host() -> None:
    """A logon id seen on another host is a different session."""
    case = CaseFile()
    case.observe(
        {
            "results": [
                {
                    "id": "trigger",
                    "type": "windows_process",
                    "host_id": "h1",
                    "properties": {"cmdline": "agent.exe --scan", "logon_id": "0x3e7"},
                },
                {
                    "id": "elsewhere",
                    "type": "windows_process",
                    "host_id": "h2",
                    "properties": {"image_path": "C:\\y.exe", "logon_id": "0x3e7"},
                },
            ]
        }
    )

    assert linked_entities(case, {"trigger"}) == []
