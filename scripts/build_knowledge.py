"""Build the agent's knowledge base from a local clone of Splunk Security Content.

Splunk Security Content is Apache-2.0 licensed; see src/bluesec1_agent/knowledge/NOTICE.
Only the fields useful for triage are kept: what a detection looks for, ATT&CK ids and known
false positives. Analytic stories and SOAR response playbooks are not built: the agent never
used them, and its investigation playbooks are written by hand in knowledge/playbooks/.

Optional Apache-2.0 sources, added to the same searchable detections file:
MITRE CAR analytics (https://github.com/mitre-attack/car) and Google-authored
Chronicle YARA-L rules (https://github.com/chronicle/detection-rules; SOC Prime and
Sigma-derived rules are skipped because they carry other licenses).

Usage:
    git clone --depth 1 --filter=blob:none --sparse https://github.com/splunk/security_content.git
    git -C security_content sparse-checkout set \
        detections/endpoint detections/network macros
    git clone --depth 1 https://github.com/mitre-attack/car.git
    git clone --depth 1 https://github.com/chronicle/detection-rules.git chronicle-rules
    uv run --with pyyaml python scripts/build_knowledge.py security_content \
        --car car --chronicle chronicle-rules
"""

import argparse
import json
import re
from pathlib import Path
from typing import Any

import yaml

KB_DIR = Path(__file__).resolve().parents[1] / "src" / "bluesec1_agent" / "knowledge"
# Field conditions from the SPL `where` clause, e.g. Processes.process_name=vssadmin.exe.
CONDITION = re.compile(
    r"(?:Processes|Filesystem|Registry|Network_Traffic|All_Traffic)\.(\w+)\s*"
    r"(=|!=|IN\b)\s*(\([^)]*\)|\"[^\"]*\"|[^\s)]+)",
    re.IGNORECASE,
)
# PowerShell script block logging (EventCode 4104) conditions.
SCRIPT_CONDITION = re.compile(
    r"\bScriptBlockText\s*(=|IN\b)\s*(\([^)]*\)|\"[^\"]*\"|[^\s)]+)", re.IGNORECASE
)
MACRO = re.compile(r"`(\w+)`")
# Fields that only list output columns, never filters.
OUTPUT_ONLY = {"dest", "user", "process_guid", "parent_process_guid", "vendor_product", "action"}


def load(path: Path) -> dict[str, Any]:
    """Parse one YAML document, returning an empty dict on errors."""
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (yaml.YAMLError, UnicodeDecodeError):
        return {}


def load_macros(root: Path) -> dict[str, str]:
    """Macro name -> SPL definition, for macros without arguments."""
    macros = {}
    for path in (root / "macros").glob("*.yml"):
        doc = load(path)
        if doc.get("name") and not doc.get("arguments"):
            macros[doc["name"]] = str(doc.get("definition") or "")
    return macros


def expand_macros(search: str, macros: dict[str, str], depth: int = 3) -> str:
    """Inline argument-free macros such as `process_powershell`."""
    for _ in range(depth):
        search = MACRO.sub(lambda match: f" {macros.get(match.group(1), '')} ", search)
    return search


def conditions(search: str, macros: dict[str, str] | None = None) -> list[str]:
    """Extract compact field conditions from an SPL search."""
    where = expand_macros(search, macros or {}).split(" BY ", 1)[0]
    found = []
    for field, operator, value in CONDITION.findall(where):
        if field.lower() in OUTPUT_ONLY:
            continue
        value = re.sub(r"\s+", " ", value.strip())[:300]
        found.append(f"{field} {operator.upper()} {value}")
    for operator, value in SCRIPT_CONDITION.findall(where):
        value = re.sub(r"\s+", " ", value.strip())[:300]
        found.append(f"script_text {operator.upper()} {value}")
    return list(dict.fromkeys(found))[:16]


def build_detections(root: Path) -> list[dict[str, Any]]:
    """Detections for endpoints."""
    macros = load_macros(root)
    records = []
    paths = sorted((root / "detections" / "endpoint").glob("*.yml"))
    paths += sorted((root / "detections" / "network").glob("*.yml"))
    for path in paths:
        doc = load(path)
        if doc.get("status") not in {"production", "experimental"}:
            continue
        tags = doc.get("tags") or {}
        records.append(
            {
                "name": doc.get("name"),
                "type": doc.get("type"),
                "mitre": tags.get("mitre_attack_id") or doc.get("mitre_attack_id") or [],
                "stories": tags.get("analytic_story") or doc.get("analytic_story") or [],
                "description": _clip(doc.get("description"), 600),
                "conditions": conditions(doc.get("search") or "", macros),
                "known_false_positives": _clip(doc.get("known_false_positives"), 500),
                "source": f"splunk/security_content:{path.relative_to(root)}",
            }
        )
    return records


def build_car(root: Path) -> list[dict[str, Any]]:
    """MITRE CAR analytics: description, ATT&CK coverage and first implementation."""
    records = []
    for path in sorted((root / "analytics").glob("*.yaml")):
        doc = load(path)
        if not doc.get("title"):
            continue
        techniques = [
            sub
            for item in doc.get("coverage") or []
            for sub in (item.get("subtechniques") or [item.get("technique")])
            if sub
        ]
        implementations = doc.get("implementations") or []
        code = next((item.get("code") for item in implementations if item.get("code")), "")
        records.append(
            {
                "name": doc["title"],
                "type": "CAR",
                "mitre": techniques,
                "stories": [],
                "description": _clip(doc.get("description"), 600),
                "conditions": [],
                "pseudocode": _clip(code, 400),
                "known_false_positives": "",
                "source": f"mitre-attack/car:{path.relative_to(root)}",
            }
        )
    return records


CLOUD_PATH = re.compile(r"aws|gcp|azure|o365|github|sap|okta|workspace|kubernetes|cloud|gemini")
YARAL_META = re.compile(r'^\s*(\w+)\s*=\s*"([^"]*)"', re.MULTILINE)
YARAL_EVENTS = re.compile(r"events:(.*?)(?:match:|outcome:|condition:)", re.DOTALL)
TECHNIQUE = re.compile(r"T\d{4}(?:[._]\d{3})?")


def build_chronicle(root: Path) -> list[dict[str, Any]]:
    """Google-authored Chronicle YARA-L rules for endpoints and networks."""
    records = []
    for path in sorted((root / "rules").rglob("*.yaral")):
        relative = str(path.relative_to(root))
        text = path.read_text(encoding="utf-8", errors="ignore")
        if "soc_prime" in relative or "sigma" in relative or CLOUD_PATH.search(relative.lower()):
            continue
        if "Google LLC" not in text[:600]:
            continue
        meta = dict(YARAL_META.findall(text))
        events = YARAL_EVENTS.search(text)
        techniques = sorted(
            {t.replace("_", ".") for t in TECHNIQUE.findall(meta.get("reference", "") + relative)}
        )
        records.append(
            {
                "name": meta.get("rule_name") or path.stem.replace("_", " "),
                "type": "Chronicle",
                "mitre": techniques,
                "stories": [],
                "description": _clip(meta.get("description"), 600),
                "conditions": [],
                "pseudocode": _clip(events.group(1) if events else "", 400),
                "known_false_positives": _clip(meta.get("false_positives"), 300),
                "source": f"chronicle/detection-rules:{relative}",
            }
        )
    return records


def _clip(value: object, limit: int) -> str:
    """Flatten whitespace and cap the length of a text field."""
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text if len(text) <= limit else f"{text[:limit]}..."


def main() -> None:
    """Write the detections as JSON Lines."""
    parser = argparse.ArgumentParser(description="Build the agent's knowledge base.")
    parser.add_argument("splunk", nargs="?", default="security_content", type=Path)
    parser.add_argument("--car", type=Path, help="Clone of mitre-attack/car.")
    parser.add_argument("--chronicle", type=Path, help="Clone of chronicle/detection-rules.")
    args = parser.parse_args()
    root = args.splunk
    detections = build_detections(root)
    if args.car:
        detections += build_car(args.car)
    if args.chronicle:
        detections += build_chronicle(args.chronicle)
    KB_DIR.mkdir(parents=True, exist_ok=True)
    for name, records in (("detections", detections),):
        path = KB_DIR / f"{name}.jsonl"
        path.write_text(
            "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records),
            encoding="utf-8",
        )
        print(f"{path.name}: {len(records)} records")


if __name__ == "__main__":
    main()
