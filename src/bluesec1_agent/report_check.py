"""Local checks of the final report before it is submitted.

A rejected report costs nothing locally, while a wrong one costs the task. The
checks are deliberately narrow: they only fire on facts the case file proves.
"""

from collections import Counter
from typing import Any

from bluesec1_agent.casefile import CaseFile
from bluesec1_agent.report_form import builtin_account, identity_is_builtin
from bluesec1_agent.signals import is_external

PROCESS_TYPES = {"windows_process", "linux_process"}
# Accounts a responder can disable or re-key: OS and directory accounts, and the
# application, service and managed accounts whose secrets an attacker can steal.
IDENTITY_TYPES = {
    "windows_user",
    "linux_user",
    "ad_object",
    "app_account",
    "service_account",
    "gmsa",
}
FILE_TYPES = {"windows_file", "linux_file", "archive_file", "email_attachment", "powershell_script"}
# Artifact kinds that name one unambiguous entity type.
KIND_ENTITY_TYPES: dict[str, set[str]] = {
    "host_to_isolate": {"host"},
    "process_observed": PROCESS_TYPES,
    "registry_observed": {"registry_key"},
    "ticket_observed": {"kerberos_ticket"},
    "lnk_observed": {"lnk_shortcut"},
    "mount_observed": {"mounted_volume", "smb_share"},
    "identity_to_rotate": IDENTITY_TYPES,
    "identity_observed": IDENTITY_TYPES,
    "file_observed": FILE_TYPES,
    "file_to_delete": FILE_TYPES,
}
MAX_PROBLEMS = 8


def check_submission(
    arguments: dict[str, Any],
    case_file: CaseFile,
    expected_verdict: str | None = None,
) -> str | None:
    """Explain what is certainly wrong with a final report, or return None.

    Args:
        arguments: Validated finishing-tool arguments.
        case_file: Everything the investigation has established.
        expected_verdict: Verdict derived from the chain assessment, if one was made.

    Returns:
        A diagnostic for the model, or None when nothing provably wrong was found.
    """
    submission = arguments.get("submission")
    if not isinstance(submission, dict):
        return None
    verdict = submission.get("verdict")
    problems: list[str] = []
    if expected_verdict and verdict != expected_verdict:
        problems.append(
            f"the chain assessment derived a {expected_verdict} verdict; submit a "
            f"{expected_verdict} report or show the evidence that changes the assessment"
        )

    artifacts = submission.get("ir_artifacts")
    if verdict == "malicious" and not artifacts:
        problems.append("a malicious verdict needs the entities that took part in the attack")
    seen: set[tuple[str, str]] = set()
    for artifact in artifacts or []:
        entity_id, kind = artifact.get("entity_id"), artifact.get("kind")
        if (entity_id, kind) in seen:
            problems.append(f"{entity_id} is listed twice as {kind}")
        seen.add((entity_id, kind))
        entity_type = case_file.entities.get(entity_id, {}).get("type")
        allowed = KIND_ENTITY_TYPES.get(kind)
        if entity_type and allowed and entity_type not in allowed:
            problems.append(
                f"{entity_id} is a {entity_type}, but kind {kind} applies to {sorted(allowed)}"
            )

    evidence = submission.get("legitimacy_evidence")
    if verdict == "benign" and not evidence:
        problems.append("a benign verdict needs the graph evidence that proves legitimacy")
    for item in evidence or []:
        if item.get("anchor") == "relation":
            relation_id = str(item.get("relation_id"))
            known = case_file.relations.get(relation_id, {}).get("properties")
            absent = [f for f in item.get("property_fields") or [] if known and f not in known]
            if absent:
                problems.append(
                    f"relation {relation_id} has no value for {absent}; "
                    f"cite only fields it has: {sorted(known or {})}"
                )
            continue
        if item.get("anchor") != "entity":
            continue
        properties = case_file.entities.get(item.get("entity_id"), {}).get("properties")
        if not properties:
            continue
        missing = [field for field in item.get("property_fields", []) if field not in properties]
        if missing:
            problems.append(
                f"entity {item['entity_id']} has no value for {missing}; "
                f"cite only fields it has: {sorted(properties)}"
            )

    if not problems:
        return None
    return "The report was not submitted: " + "; ".join(problems[:MAX_PROBLEMS]) + "."


# The runtime's artifact-kind contract: connection telemetry lives on relations, and
# entity-level forensic rows for connections would double-count it.
TELEMETRY_ONLY_TYPES = {"network_connection"}
# Script blocks and cmdlet invocations are logging records of a process, not objects a
# responder acts on: no artifact kind fits them (in practice they were never evidence),
# and the process that ran them carries the finding.
TELEMETRY_RECORD_TYPES = {"powershell_cmdlet_invocation", "powershell_script"}
# Catch-all kinds that name no concrete response action; in practice they were almost
# never what the case needed, and each wrong artifact costs as much as a missing one.
CATCH_ALL_KINDS = {"other", "cleanup_to_verify"}
# Response actions that are the core of any report and are never filtered.
CORE_KINDS = {"host_to_isolate", "identity_to_rotate"}
# Legitimacy evidence is scored for precision: in a controlled practice experiment the
# trigger and the next two items scored about 0.18 higher than the same reports with up
# to seven items.
MAX_LEGITIMACY_EVIDENCE = 3


def trigger_first(evidence: list[dict[str, Any]], trigger_ids: set[str]) -> list[dict[str, Any]]:
    """Legitimacy evidence with the alert's own entity moved to the front."""
    trigger = [item for item in evidence if item.get("entity_id") in trigger_ids][:1]
    return trigger + [item for item in evidence if item not in trigger]


def external_endpoint(entry: dict[str, Any]) -> bool:
    """An entity that stands for a place outside the organisation.

    A connection carries an external-address signal; an external host has no
    connection signal, but its role or its own address says it is outside.
    """
    if any("external address" in signal for signal in entry.get("signals", [])):
        return True
    properties = entry.get("properties") or {}
    if str(properties.get("role", "")).lower() == "external":
        return True
    return any(
        isinstance(properties.get(key), str) and is_external(properties[key])
        for key in ("ip", "dst_ip")
    )


def filter_artifacts(
    arguments: dict[str, Any],
    chain: set[str],
    case_file: CaseFile,
    trigger_ids: set[str] | None = None,
    benign_cap: int | None = MAX_LEGITIMACY_EVIDENCE,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Keep only artifacts the accepted attack chain supports, and benign evidence short.

    Forensic `*_observed` artifacts are never reported for network connections (the
    runtime's contract keeps that telemetry on relations), catch-all kinds are dropped,
    and the rest must name an entity of the chain; `network_block` needs a chain entity,
    an external connection or an external host.
    Hosts, accounts and the other response actions always stay. A report the filter
    would empty is kept as is. Benign evidence keeps the trigger's item first and at
    most `benign_cap` items; None leaves it untouched.

    Args:
        arguments: Finishing-tool arguments with a malicious submission.
        chain: Entity ids of accepted stages and unexplained signals.
        case_file: Everything the investigation established.

    Returns:
        The filtered arguments and the dropped artifacts.
    """
    submission = arguments.get("submission")
    if not isinstance(submission, dict):
        return arguments, []
    if submission.get("verdict") == "benign":
        if benign_cap is None:
            return arguments, []
        evidence = trigger_first(submission.get("legitimacy_evidence") or [], trigger_ids or set())
        if len(evidence) <= benign_cap:
            if evidence == (submission.get("legitimacy_evidence") or []):
                return arguments, []
            return {**arguments, "submission": {**submission, "legitimacy_evidence": evidence}}, []
        # The model lists the decisive facts first (trigger, context, the answer to the
        # strongest signal); the tail is what merely looked normal.
        return (
            {
                **arguments,
                "submission": {**submission, "legitimacy_evidence": evidence[:benign_cap]},
            },
            evidence[benign_cap:],
        )
    if submission.get("verdict") != "malicious":
        return arguments, []
    artifacts = submission.get("ir_artifacts") or []
    kept: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    for artifact in artifacts:
        entity_id, kind = artifact.get("entity_id"), str(artifact.get("kind"))
        external = external_endpoint(case_file.entities.get(entity_id, {}))
        entity_type = case_file.entities.get(entity_id, {}).get("type")
        if (
            kind in CATCH_ALL_KINDS
            or (kind.endswith("_observed") and entity_type in TELEMETRY_ONLY_TYPES)
            or entity_type in TELEMETRY_RECORD_TYPES
        ):
            dropped.append(artifact)
        elif kind in CORE_KINDS or entity_id in chain:
            kept.append(artifact)
        elif kind == "network_block":
            (kept if external else dropped).append(artifact)
        elif kind.endswith("_observed"):
            dropped.append(artifact)
        else:
            kept.append(artifact)
    if not kept or not dropped:
        return arguments, []
    return {**arguments, "submission": {**submission, "ir_artifacts": kept}}, dropped


def vote_reports(
    reports: list[dict[str, Any]], verdict: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Merge independently written reports, keeping what most of them agree on.

    A wrong artifact costs as much as a missing one, and the artifacts a model adds
    on a whim differ from sample to sample while the ones the evidence demands
    repeat. So an artifact (entity and kind) or a legitimacy fact (anchor and field)
    stays when a majority of the reports name it. Hosts and accounts to act on stay
    when any report names them: a missed compromised host costs most.

    Args:
        reports: Finishing-tool arguments of each sample.
        verdict: The verdict the code derived; reports with another verdict are ignored.

    Returns:
        The merged finishing-tool arguments, built on the first agreeing report, and
        the vote counts for the trajectory.
    """
    agreeing = [
        report
        for report in reports
        if isinstance(report.get("submission"), dict)
        and report["submission"].get("verdict") == verdict
    ] or reports
    base = agreeing[0]
    if len(agreeing) < 2 or not isinstance(base.get("submission"), dict):
        return base, {"samples": len(agreeing)}
    need = len(agreeing) // 2 + 1
    submission = base["submission"]
    if verdict == "malicious":
        first: dict[tuple[str, str], dict[str, Any]] = {}
        counts: Counter[tuple[str, str]] = Counter()
        for report in agreeing:
            keys = {}
            for artifact in report["submission"].get("ir_artifacts") or []:
                key = (str(artifact.get("entity_id")), str(artifact.get("kind")))
                keys[key] = artifact
            for key, artifact in keys.items():
                first.setdefault(key, artifact)
                counts[key] += 1
        kept = [
            artifact
            for key, artifact in first.items()
            if counts[key] >= need or key[1] in CORE_KINDS
        ]
        votes = {"samples": len(agreeing), "kept": len(kept), "candidates": len(first)}
        if not kept:
            return base, votes
        return {**base, "submission": {**submission, "ir_artifacts": kept}}, votes

    anchors: dict[tuple[str, str], dict[str, Any]] = {}
    anchor_counts: Counter[tuple[str, str]] = Counter()
    fields: dict[tuple[str, str], Counter[str]] = {}
    for report in agreeing:
        seen: dict[tuple[str, str], dict[str, Any]] = {}
        for item in report["submission"].get("legitimacy_evidence") or []:
            key = (str(item.get("anchor")), str(item.get("entity_id") or item.get("relation_id")))
            seen.setdefault(key, item)
        for key, item in seen.items():
            anchors.setdefault(key, item)
            anchor_counts[key] += 1
            # Counter keeps first-seen order, so fields stay in the order models cite them.
            fields.setdefault(key, Counter()).update(
                dict.fromkeys(item.get("property_fields") or [], 1)
            )
    evidence = []
    for key, item in anchors.items():
        if anchor_counts[key] < need:
            continue
        agreed = [name for name, count in fields[key].items() if count >= need]
        evidence.append({**item, "property_fields": agreed} if agreed else item)
    votes = {"samples": len(agreeing), "kept": len(evidence), "candidates": len(anchors)}
    if not evidence:
        return base, votes
    return {**base, "submission": {**submission, "legitimacy_evidence": evidence}}, votes


BENIGN_SHAPES = ("core_people", "core", "model")
MAX_OTHER_PEOPLE = 2
TRIGGER_FIELDS = ("image_path", "signer", "parent_image", "user", "cmdline")
# Binaries of the operating system: a file kind on their process is a mistake to send
# back to the model, never a deletion of the system file.
SYSTEM_PATH_PREFIXES = (
    "c:\\windows\\",
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
    "/usr/lib/",
    "/lib/",
)
# Accounts that name who acted in a legitimacy argument. A local account (the machine's
# own Administrator) or one with no type names no one: in practice runs they were never
# legitimacy evidence, while domain and managed service accounts nearly always were.
PERSON_ACCOUNT_TYPES = {"domain", "managed_service", "service"}


def _names_someone(properties: dict[str, Any]) -> bool:
    """Whether an account entity identifies a person or a managed service."""
    if identity_is_builtin(properties):
        return False
    return str(properties.get("account_type", "")).lower() in PERSON_ACCOUNT_TYPES


def _account_item(case_file: CaseFile, entity_id: str) -> dict[str, Any] | None:
    """An account as legitimacy evidence, citing only fields it has values for."""
    properties = case_file.entities.get(entity_id, {}).get("properties") or {}
    filled = [name for name, value in properties.items() if value not in (None, "", [], {})]
    preferred = [
        name for name in ("username", "group_memberships", "account_type") if name in filled
    ]
    fields = preferred or filled[:2]
    if not fields:
        return None
    return {"anchor": "entity", "entity_id": entity_id, "property_fields": fields}


def _trigger_process(case_file: CaseFile, trigger_ids: set[str]) -> str | None:
    """The alert's process entity, if the alert names one."""
    return next(
        (
            entity_id
            for entity_id in sorted(trigger_ids)
            if str(case_file.entities.get(entity_id, {}).get("type", "")).endswith("_process")
        ),
        None,
    )


def _trigger_item(case_file: CaseFile, trigger_ids: set[str]) -> dict[str, Any] | None:
    """The alert's process as legitimacy evidence, for a report that left it out."""
    entity_id = _trigger_process(case_file, trigger_ids)
    if entity_id is None:
        return None
    properties = case_file.entities[entity_id].get("properties") or {}
    fields = [name for name in TRIGGER_FIELDS if properties.get(name) not in (None, "", [], {})]
    if not fields:
        return None
    return {"anchor": "entity", "entity_id": entity_id, "property_fields": fields}


def _trigger_account(case_file: CaseFile, trigger_ids: set[str]) -> str | None:
    """The opened account entity the trigger process ran as, if it names someone."""
    process_id = _trigger_process(case_file, trigger_ids)
    if process_id is None:
        return None
    process = case_file.entities[process_id].get("properties") or {}
    user = str(process.get("user") or "").lower().rsplit("\\", 1)[-1]
    sid = str(process.get("user_sid") or "")
    if not user and not sid or builtin_account(sid or user) or builtin_account(user):
        return None
    for entity_id, entry in case_file.entities.items():
        if entry.get("type") not in {"windows_user", "linux_user"}:
            continue
        properties = entry.get("properties") or {}
        if not _names_someone(properties):
            continue
        if (sid and properties.get("sid") == sid) or (
            user and str(properties.get("username", "")).lower() == user
        ):
            return entity_id
    return None


def shape_benign_report(
    arguments: dict[str, Any], case_file: CaseFile, trigger_ids: set[str], shape: str
) -> tuple[dict[str, Any], list[str]]:
    """Keep a benign report to the facts that prove legitimacy: what ran and who did it.

    Benign quality rewards precision: in practice runs the trigger alone scored about
    0.55, each named account that acted added to it, and almost every other item cost
    more often than it paid. So the report keeps the alert's process (added when the
    model left it out) and the named account it ran as; "core_people" also keeps up to
    two other named accounts the investigation opened (the ones the model cited first),
    "core" only another one the model cited, and "model" leaves the report as written.

    Returns:
        The reshaped arguments (the same object when nothing changes) and the ids of
        the items it holds that the model had not cited.
    """
    submission = arguments.get("submission")
    if shape == "model" or not isinstance(submission, dict):
        return arguments, []
    if submission.get("verdict") != "benign":
        return arguments, []
    evidence = list(submission.get("legitimacy_evidence") or [])
    process_id = _trigger_process(case_file, trigger_ids)
    cited_process = [item for item in evidence if item.get("entity_id") == process_id][:1]
    built_process = _trigger_item(case_file, trigger_ids)
    kept = cited_process or ([built_process] if built_process is not None else [])
    if not kept:
        return arguments, []
    cited = [str(item.get("entity_id")) for item in evidence]
    if (account := _trigger_account(case_file, trigger_ids)) is not None:
        cited_account = [item for item in evidence if item.get("entity_id") == account][:1]
        built = _account_item(case_file, account)
        kept += cited_account or ([built] if built is not None else [])
    present = {str(item.get("entity_id")) for item in kept}
    if shape == "core_people":
        candidates = sorted(
            (
                entity_id
                for entity_id, entry in case_file.entities.items()
                if entry.get("type") in {"windows_user", "linux_user"}
                and (entry.get("properties") or {}).get("username")
                and _names_someone(entry.get("properties") or {})
            ),
            key=lambda entity_id: entity_id not in cited,
        )
        limit = MAX_OTHER_PEOPLE
    else:
        candidates = [
            entity_id
            for entity_id in cited
            if case_file.entities.get(entity_id, {}).get("type") in {"windows_user", "linux_user"}
            and _names_someone(case_file.entities[entity_id].get("properties") or {})
        ]
        limit = 1
    others = [entity_id for entity_id in candidates if entity_id not in present][:limit]
    for entity_id in others:
        cited_item = next((item for item in evidence if item.get("entity_id") == entity_id), None)
        if (item := cited_item or _account_item(case_file, entity_id)) is not None:
            kept.append(item)
    if kept == evidence:
        return arguments, []
    added = [str(item.get("entity_id")) for item in kept if str(item.get("entity_id")) not in cited]
    return {**arguments, "submission": {**submission, "legitimacy_evidence": kept}}, added


def retarget_file_artifacts(
    arguments: dict[str, Any], case_file: CaseFile
) -> tuple[dict[str, Any], list[str]]:
    """Point file kinds named on a process at the file of its image on the same host.

    A model sometimes reports file_to_delete or file_observed with the id of the
    process that ran the file; the response targets the file on disk. Processes of
    operating-system binaries are left alone: the submission check sends that mistake
    back to the model rather than turning it into deleting a system file.

    Returns:
        The corrected arguments (the same object when nothing changes) and the
        process ids that were replaced.
    """
    submission = arguments.get("submission")
    if not isinstance(submission, dict) or submission.get("verdict") != "malicious":
        return arguments, []
    files_by_path: dict[tuple[Any, str], str] = {}
    for entity_id, entry in case_file.entities.items():
        if entry.get("type") in FILE_TYPES:
            path = str((entry.get("properties") or {}).get("path") or "").lower()
            if path:
                files_by_path[(case_file.raw.get(entity_id, {}).get("host_id"), path)] = entity_id
    artifacts = list(submission.get("ir_artifacts") or [])
    reported = {(str(a.get("entity_id")), str(a.get("kind"))) for a in artifacts}
    replaced: list[str] = []
    corrected: list[dict[str, Any]] = []
    for artifact in artifacts:
        entity_id, kind = str(artifact.get("entity_id")), str(artifact.get("kind"))
        entry = case_file.entities.get(entity_id, {})
        image = str((entry.get("properties") or {}).get("image_path") or "").lower()
        target = (
            files_by_path.get((case_file.raw.get(entity_id, {}).get("host_id"), image))
            if kind in {"file_to_delete", "file_observed"}
            and str(entry.get("type", "")).endswith("_process")
            and image
            and not image.startswith(SYSTEM_PATH_PREFIXES)
            else None
        )
        if target is None:
            corrected.append(artifact)
            continue
        replaced.append(entity_id)
        if (target, kind) not in reported:
            corrected.append({**artifact, "entity_id": target})
            reported.add((target, kind))
    if not replaced:
        return arguments, []
    return {**arguments, "submission": {**submission, "ir_artifacts": corrected}}, replaced
