from bluesec1_agent.casefile import CaseFile, compact

ENTITY = {
    "id": "process-1",
    "type": "windows_process",
    "properties": {"image_path": "C:\\x.exe", "cmdline": None, "pid": 42, "loaded_modules": []},
    "relation_ids": {"incoming": ["rel-1"], "outgoing": []},
}
RELATION = {"id": "rel-1", "type": "parent_of", "source_id": "p0", "target_id": "process-1"}


def test_compact_drops_empty_fields_and_decodes_json_strings() -> None:
    result = compact('{"results": [{"a": null, "b": "", "c": 1}], "next_page_id": null}')

    assert result == {"results": [{"c": 1}]}


def test_case_file_counts_only_new_objects() -> None:
    case_file = CaseFile()

    # Entity, relation, and the entity's relation ids learned.
    assert case_file.observe(compact([ENTITY, RELATION])) == 3
    assert case_file.observe(compact(ENTITY)) == 0
    rendered = case_file.render()
    assert "process-1 [windows_process]" in rendered
    assert "rel-1 [parent_of] p0 -> process-1" in rendered
    assert "cmdline" not in rendered


def test_case_file_render_respects_budget() -> None:
    case_file = CaseFile()
    for index in range(50):
        case_file.observe({"id": f"e{index}", "type": "file", "properties": {"path": "x" * 300}})

    assert len(case_file.render(max_chars=10_000)) < 12_000


def test_case_file_flags_repeated_external_connections_as_beaconing() -> None:
    case_file = CaseFile()
    for index in range(6):
        case_file.observe(
            {
                "id": f"c{index}",
                "type": "network_connection",
                "properties": {"dst_ip": "198.51.100.7", "fqdn": "cdn.example", "dst_port": 443},
            }
        )

    assert any("beaconing" in signal for signal in case_file.strong_signals())


def test_case_file_answers_known_lookups_and_lists_leads() -> None:
    case_file = CaseFile()
    case_file.observe(compact([ENTITY, RELATION]))
    case_file.observe(
        compact(
            {
                "id": "evil",
                "type": "windows_process",
                "properties": {"image_path": "C:\\Users\\Public\\svchost.exe"},
            }
        )
    )

    assert case_file.cached({"relation_id": "rel-1", "reasoning": "x"})["type"] == "parent_of"
    assert case_file.cached({"entity_id": "process-1"})["relation_ids"]
    assert case_file.cached({"entity_id": "evil"}) is None
    assert case_file.relation_overview("process-1")["known"]["rel-1"].startswith("parent_of")
    leads = case_file.open_leads()
    assert leads[0].startswith("evil")
    assert any(lead.startswith("p0") for lead in leads)


def test_ad_lookups_count_as_progress() -> None:
    case_file = CaseFile()

    assert case_file.observe({"id": "ad-1", "sam_account_name": "bob"}, ad_context=True) == 1
    assert case_file.observe({"id": "ad-1", "sam_account_name": "bob"}, ad_context=True) == 0


def test_compact_hides_the_ground_truth_marker() -> None:
    """The benchmark's ground-truth marker never reaches the model; real sources stay."""
    relation = {
        "id": "r1",
        "log_sources": ["ground_truth_only"],
        "other": {"log_sources": ["WinEvt-4624", "ground_truth_only"]},
    }

    assert compact(relation) == {"id": "r1", "other": {"log_sources": ["WinEvt-4624"]}}


def test_relation_properties_are_kept_and_rendered() -> None:
    """Logon type and source survive compaction into the case file."""
    case = CaseFile()
    case.observe(
        {
            "results": [
                {
                    "kind": "relation",
                    "id": "r1",
                    "type": "logged_on_to",
                    "source_id": "u1",
                    "target_id": "h1",
                    "log_sources": ["WinEvt-4624"],
                    "logon_properties": {"logon_type": "network", "source_ip": "10.0.0.5"},
                }
            ]
        }
    )

    assert case.relations["r1"]["properties"] == {"logon_type": "network", "source_ip": "10.0.0.5"}
    assert '"source_ip":"10.0.0.5"' in case.render()


def test_case_file_records_what_each_search_covered() -> None:
    case_file = CaseFile()
    case_file.record_search(
        {"query": "evil.ps1", "scope": {"kind": "entity", "type": "windows_file"}},
        {"results": [{"kind": "entity", "id": "f1", "type": "windows_file"}], "next_page_id": 2},
    )
    case_file.record_search(
        {"query": "0x1f", "time_window": {"from": "08:00", "to": "09:00"}}, {"results": []}
    )
    case_file.record_search({"entity_id": "f1"}, {"id": "f1"})

    lines = case_file.coverage()
    assert lines == [
        "- 'evil.ps1' [windows_file]: 1 windows_file; more pages unread",
        "- '0x1f' 08:00..09:00: nothing found",
    ]
    assert "Searches made (2" in case_file.render()
