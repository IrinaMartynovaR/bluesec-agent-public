from bluesec1_agent.signals import entity_signals


def test_flags_masquerading_from_user_writable_path() -> None:
    signals = entity_signals(
        "windows_process",
        {
            "image_path": "C:\\Users\\bob\\AppData\\Local\\Temp\\svchost.exe",
            "cmdline": "svchost.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8A",
        },
    )

    assert any("masquerading" in signal for signal in signals)
    assert any("user-writable" in signal for signal in signals)
    # Command-line techniques come from the knowledge base, not from patterns here.
    assert not any("encoded" in signal for signal in signals)


def test_reports_benign_facts_for_signed_system_binary() -> None:
    signals = entity_signals(
        "windows_process",
        {
            "image_path": "C:\\Windows\\System32\\wsmprovhost.exe",
            "parent_image": "C:\\Windows\\System32\\svchost.exe",
            "signer": "Microsoft Windows",
            "original_filename": "wsmprovhost.exe",
        },
    )

    assert signals == ["benign: Microsoft-signed binary in its system directory"]


def test_flags_external_destination_only() -> None:
    assert entity_signals("network_connection", {"dst_ip": "10.0.0.5", "dst_port": 445}) == []
    assert entity_signals("network_connection", {"dst_ip": "203.0.113.9", "dst_port": 443})


def test_lookalike_names_are_caught_and_ordinary_ones_are_not() -> None:
    from bluesec1_agent.signals import lookalike, mixed_scripts

    assert lookalike("svch0st.exe", "svchost.exe")
    assert lookalike("adm_j.d0e", "adm_j.doe")
    assert lookalike("adm_j.deo", "adm_j.doe")
    assert lookalike("svhcost.exe", "svchost.exe", same_length=True)
    assert not lookalike("service.exe", "services.exe", same_length=True)
    assert not lookalike("a.turner", "m.turner")
    assert not lookalike("ssms.exe", "smss.exe")
    assert not lookalike("user01", "user02")
    assert mixed_scripts("Аdministrator")  # Cyrillic А
    assert not mixed_scripts("Administrator")
