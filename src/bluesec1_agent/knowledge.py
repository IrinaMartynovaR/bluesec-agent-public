"""Detection knowledge the agent consults instead of hard-coded prompt playbooks.

The records come from Splunk Security Content (Apache-2.0, see knowledge/NOTICE):
what each detection looks for, its ATT&CK ids and its known false positives. The
model searches them through a local tool that costs no score, and process entities
are matched against detection conditions automatically, so knowledge about attacks
and their legitimate look-alikes reaches the verdict without tuning the prompt to
the practice cases.
"""

import fnmatch
import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any

KNOWLEDGE_DIR = Path(__file__).resolve().parent / "knowledge"
KINDS = ("detections",)
PLAYBOOKS_DIR = KNOWLEDGE_DIR / "playbooks"
GUIDE_LIST_FIELDS = ("processes", "parents", "entity_types", "signals")
TYPE_RANK = {"TTP": 0, "Anomaly": 1, "Hunting": 2}
AUTO_MATCH_TYPES = {"TTP", "Anomaly"}
# Share of a query's IDF weight a record has to contain to be returned.
MIN_MATCHED_WEIGHT = 0.4
RANKERS = ("idf", "bm25", "hybrid")
# Reciprocal rank fusion constant and how deep each ranking is fused.
RRF_K = 60
RRF_DEPTH = 20
_TOKEN = re.compile(r"[a-z0-9]+")
STRONG_FIELDS = ("name", "conditions", "mitre")
_CONDITION = re.compile(r"^(\w+) (=|IN) (.+)$")
_QUOTED = re.compile(r'"([^"]*)"')
_WORD = re.compile(r"[a-z0-9][a-z0-9._$-]*")
# Words that carry no detection meaning in the model's questions.
STOP_WORDS = {
    "the",
    "and",
    "for",
    "with",
    "from",
    "into",
    "via",
    "that",
    "this",
    "are",
    "was",
    "not",
    "false",
    "positive",
    "positives",
    "legitimate",
    "benign",
    "malicious",
    "suspicious",
    "detection",
    "detect",
    "activity",
    "process",
    "processes",
    "windows",
    "using",
    "use",
}

SEARCH_TOOL = {
    "name": "knowledge_search",
    "description": (
        "Search the detection knowledge base (free: no score cost). Returns how a technique "
        "or tool is detected, its ATT&CK ids and its known false positives. Use it to decide "
        "whether an observed behaviour is attacker activity or a legitimate look-alike."
    ),
    "parameters": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "query": {
                "type": "string",
                "minLength": 3,
                "description": "A few keywords: tool, binary, command fragment or ATT&CK id, "
                "e.g. 'wsmprovhost powershell', 'comsvcs minidump', 'T1003.001'.",
            },
            "kind": {
                "enum": ["detections", "playbooks"],
                "description": "detections (default) or playbooks (how to investigate and "
                "report one type of alert).",
            },
        },
        "required": ["query"],
    },
}


@dataclass(frozen=True)
class Terms:
    """Substring conditions on one text field: all `=` terms (majority) and each IN group."""

    required: tuple[str, ...] = ()
    groups: tuple[tuple[str, ...], ...] = ()

    def __bool__(self) -> bool:
        return bool(self.required or self.groups)

    def score(self, text: str) -> int:
        """Satisfied conditions, or -1 when the text does not fit."""
        points = 0
        # Short lists are one AND clause; long ones are OR branches flattened together,
        # of which a majority has to match.
        if self.required:
            hits = sum(_contains(text, term) for term in self.required)
            needed = len(self.required) if len(self.required) <= 3 else len(self.required) // 2 + 1
            if hits < needed:
                return -1
            points += hits
        for group in self.groups:
            if not any(_contains(text, term) for term in group):
                return -1
            points += 1
        return points


@dataclass(frozen=True)
class Matcher:
    """Conditions of one detection, flattened from its SPL search."""

    names: tuple[str, ...] = ()
    parents: tuple[str, ...] = ()
    command: Terms = field(default_factory=Terms)
    script: Terms = field(default_factory=Terms)
    registry_paths: tuple[str, ...] = ()
    registry_values: Terms = field(default_factory=Terms)

    @property
    def usable(self) -> bool:
        """Only conditions specific enough to name an image, script or key count."""
        return bool(self.names or self.parents or self.script or self.registry_paths)

    def score_process(self, name: str, original: str, parent: str, cmdline: str) -> int:
        """Satisfied conditions for a process, or 0 on a mismatch."""
        if self.registry_paths:
            return 0
        points = 0
        if self.names:
            if not any(_like(name, v) or _like(original, v) for v in self.names):
                return 0
            points += 1
        if self.parents:
            if not any(_like(parent, value) for value in self.parents):
                return 0
            points += 1
        for terms in (self.command, self.script):
            if terms:
                terms_points = terms.score(cmdline)
                if terms_points < 0:
                    return 0
                points += terms_points
        return points

    def score_script(self, text: str) -> int:
        """Satisfied script-block conditions, or 0 on a mismatch."""
        if not self.script:
            return 0
        return max(self.script.score(text), 0)

    def score_registry(self, path: str, value_text: str) -> int:
        """Satisfied registry conditions, or 0 on a mismatch."""
        if not self.registry_paths or not any(_like(path, v) for v in self.registry_paths):
            return 0
        if self.registry_values:
            value_points = self.registry_values.score(value_text)
            return 0 if value_points < 0 else 1 + value_points
        return 1


class Bm25Index:
    """BM25F-lite over one kind of records: whole-word matching, length normalisation.

    Fields that name what a record detects (name, conditions, ATT&CK ids) are boosted
    by repeating their tokens, the usual cheap approximation of BM25F.
    """

    K1 = 1.2
    B = 0.75
    FIELD_BOOST = {"name": 3, "conditions": 2, "mitre": 2}

    def __init__(self, records: list[dict[str, Any]]) -> None:
        """Tokenise every record and collect document frequencies."""
        self.documents: list[Counter[str]] = []
        self.lengths: list[int] = []
        frequency: Counter[str] = Counter()
        for record in records:
            tokens = _tokens(json.dumps(record, ensure_ascii=False))
            for field_name, boost in self.FIELD_BOOST.items():
                tokens += _tokens(json.dumps(record.get(field_name, ""))) * (boost - 1)
            counts = Counter(tokens)
            self.documents.append(counts)
            self.lengths.append(len(tokens))
            frequency.update(counts.keys())
        self.frequency = frequency
        self.average_length = sum(self.lengths) / max(len(self.lengths), 1)

    def idf(self, term: str) -> float | None:
        """BM25 inverse document frequency, None for words no record contains."""
        documents_with_term = self.frequency.get(term, 0)
        if not documents_with_term:
            return None
        total = len(self.documents)
        return math.log(1 + (total - documents_with_term + 0.5) / (documents_with_term + 0.5))

    def rank(self, terms: list[str]) -> list[tuple[float, float, int]]:
        """(score, share of the query's IDF matched, record index) for matching records."""
        weights = {term: weight for term in terms if (weight := self.idf(term)) is not None}
        total = sum(weights.values())
        ranked = []
        for index, counts in enumerate(self.documents):
            matched = [term for term in weights if term in counts]
            if not matched:
                continue
            norm = self.K1 * (1 - self.B + self.B * self.lengths[index] / self.average_length)
            score = sum(
                weights[term] * counts[term] * (self.K1 + 1) / (counts[term] + norm)
                for term in matched
            )
            ranked.append((score, sum(weights[t] for t in matched) / total, index))
        return ranked


class KnowledgeBase:
    """Searchable detections and the investigation playbooks."""

    def __init__(self, records: dict[str, list[dict[str, Any]]], ranker: str = "hybrid") -> None:
        """Index records and precompute process matchers.

        Args:
            records: Records per kind, as written by scripts/build_knowledge.py.
            ranker: "idf" (substring match weighted by IDF), "bm25" (BM25F over words) or
                "hybrid" (both fused by reciprocal rank, the default).
        """
        if ranker not in RANKERS:
            raise ValueError(f"ranker must be one of {RANKERS}")
        self.records = records
        self.ranker = ranker
        self._bm25: dict[str, Bm25Index] = {}
        self._texts: dict[int, str] = {}
        self._idfs: dict[tuple[str, str], float | None] = {}
        self.matchers = [
            (record, matcher)
            for record in records.get("detections", [])
            # Hunting analytics are broad by design; they stay searchable, not auto-matched.
            if record.get("type") in AUTO_MATCH_TYPES
            and (matcher := _matcher(record.get("conditions", []))).usable
        ]

    @classmethod
    def load(
        cls, directory: Path = KNOWLEDGE_DIR, ranker: str = "hybrid"
    ) -> "KnowledgeBase | None":
        """Read the knowledge base, or return None when it has not been built."""
        records = {}
        for kind in KINDS:
            path = directory / f"{kind}.jsonl"
            if not path.exists():
                return None
            records[kind] = [
                json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line
            ]
        records["guides"] = load_guides(directory / PLAYBOOKS_DIR.name)
        return cls(records, ranker)

    def guide(self, name: str) -> str | None:
        """Full text of the guide whose file stem or name contains `name`."""
        for record in self.records.get("guides", []):
            if name in (record.get("stem"), record.get("name")):
                return describe(record)
        return None

    def match_guides(
        self,
        entity_type: str | None,
        properties: dict[str, Any],
        signals: list[str],
        is_trigger: bool = True,
    ) -> list[str]:
        """Stems of guides whose triggers an entity matches.

        Args:
            entity_type: Graph entity type.
            properties: Entity properties.
            signals: Structural signals computed for the entity.
            is_trigger: The entity is named by the alert. Guides marked `trigger_only`
                describe one kind of alert and are offered only for its trigger.

        Returns:
            Guide stems, in catalog order.
        """
        image = _basename(str(properties.get("image_path", "")))
        matched = []
        for record in self.records.get("guides", []):
            if record.get("always", "").lower() == "true":
                if is_trigger:
                    matched.append(str(record["stem"]))
                continue
            if record.get("trigger_only", "").lower() == "true" and not is_trigger:
                continue
            parent = _basename(str(properties.get("parent_image", "")))
            if record.get("parents") and parent not in record["parents"]:
                continue
            if (
                (image and image in record.get("processes", []))
                or entity_type in record.get("entity_types", [])
                or any(
                    trigger in signal for trigger in record.get("signals", []) for signal in signals
                )
            ):
                matched.append(str(record["stem"]))
        return matched

    def search(self, query: str, kind: str = "detections", limit: int = 5) -> list[str]:
        """Return the records that best match a free-text query.

        Models ask in sentences, so words are weighted by how rare they are in the
        knowledge base (IDF): a tool name such as `sdelete` decides the match, a word
        such as `binary` barely counts. Name, conditions and ATT&CK ids weigh double.
        A record must carry at least `MIN_MATCHED_WEIGHT` of the query's total weight.

        Args:
            query: Free text or keywords.
            kind: "detections" or "playbooks".
            limit: Maximum records returned.

        Returns:
            Compact record descriptions, best first.
        """
        kind = "guides" if kind == "playbooks" else kind
        records = self.records.get(kind, [])
        if self.ranker == "bm25":
            return [describe(records[i]) for i in self._rank_bm25(query, kind)[:limit]]
        if self.ranker == "hybrid":
            fused: dict[int, float] = {}
            for ranking in (self._rank_idf(query, kind), self._rank_bm25(query, kind)):
                for position, index in enumerate(ranking[:RRF_DEPTH]):
                    fused[index] = fused.get(index, 0.0) + 1.0 / (RRF_K + position + 1)
            order = sorted(fused, key=lambda index: -fused[index])
            return [describe(records[index]) for index in order[:limit]]
        return [describe(records[i]) for i in self._rank_idf(query, kind)[:limit]]

    def _rank_idf(self, query: str, kind: str) -> list[int]:
        """Record indexes ranked by IDF-weighted substring matches."""
        records = self.records.get(kind, [])
        terms = [
            term
            for term in dict.fromkeys(_WORD.findall(query.lower()))
            if term not in STOP_WORDS and len(term) > 2
        ]
        if not terms or not records:
            return []
        # Words absent from the knowledge base cannot match anything; leaving them in
        # the total would only make every record look like a weak match.
        weights = {term: weight for term in terms if (weight := self._idf(kind, term)) is not None}
        if not weights:
            return []
        terms = list(weights)
        total = sum(weights.values())
        scored = []
        for index, record in enumerate(records):
            text = self._text(record)
            matched = [term for term in terms if term in text]
            matched_weight = sum(weights[term] for term in matched)
            if not matched or matched_weight < MIN_MATCHED_WEIGHT * total:
                continue
            strong_text = self._strong_text(record)
            score = matched_weight + sum(weights[t] for t in matched if t in strong_text)
            scored.append((-score, TYPE_RANK.get(str(record.get("type")), 3), index))
        scored.sort()
        return [index for *_, index in scored]

    def _rank_bm25(self, query: str, kind: str) -> list[int]:
        """Record indexes ranked by BM25F, with the same minimum matched query weight."""
        records = self.records.get(kind, [])
        terms = [
            term
            for term in dict.fromkeys(_tokens(query))
            if term not in STOP_WORDS and len(term) > 2
        ]
        if not terms or not records:
            return []
        if kind not in self._bm25:
            self._bm25[kind] = Bm25Index(records)
        ranked = [
            (-score, TYPE_RANK.get(str(records[index].get("type")), 3), index)
            for score, share, index in self._bm25[kind].rank(terms)
            if share >= MIN_MATCHED_WEIGHT
        ]
        ranked.sort()
        return [index for *_, index in ranked]

    def _idf(self, kind: str, term: str) -> float | None:
        """Inverse document frequency of a word among one kind of records, None if absent."""
        key = (kind, term)
        if key not in self._idfs:
            records = self.records.get(kind, [])
            frequency = sum(term in self._text(record) for record in records)
            self._idfs[key] = (
                math.log((len(records) + 1) / (frequency + 1)) + 1.0 if frequency else None
            )
        return self._idfs[key]

    def _text(self, record: dict[str, Any]) -> str:
        """Whole record as lower-case text, cached per record."""
        key = id(record)
        if key not in self._texts:
            self._texts[key] = json.dumps(record, ensure_ascii=False).lower()
        return self._texts[key]

    def _strong_text(self, record: dict[str, Any]) -> str:
        """Name, conditions and ATT&CK ids as lower-case text."""
        return json.dumps([record.get(name, "") for name in STRONG_FIELDS]).lower()

    def match_entity(
        self,
        entity_type: str | None,
        properties: dict[str, Any],
        limit: int = 3,
    ) -> list[str]:
        """Detections whose conditions fit a process, script block or registry key.

        Args:
            entity_type: Graph entity type.
            properties: Entity properties.
            limit: Maximum matches returned.

        Returns:
            Short match descriptions with ATT&CK ids and known false positives.
        """
        if entity_type in {"windows_process", "linux_process"}:
            name = _basename(str(properties.get("image_path", "")))
            if not name:
                return []
            args = (
                name,
                str(properties.get("original_filename", "")).lower(),
                _basename(str(properties.get("parent_image", ""))),
                str(properties.get("cmdline", "")).lower(),
            )

            def score(matcher: Matcher) -> int:
                return matcher.score_process(*args)

            threshold = 2
        elif entity_type == "powershell_script":
            text = str(properties.get("script_text", "")).lower()

            def score(matcher: Matcher) -> int:
                return matcher.score_script(text)

            threshold = 1
        elif entity_type == "registry_key":
            path = str(properties.get("path", "")).lower()
            value_text = f"{properties.get('value_name', '')} {properties.get('value_data', '')}"

            def score(matcher: Matcher) -> int:
                return matcher.score_registry(path, value_text.lower())

            threshold = 1
        else:
            return []
        matches = []
        for record, matcher in self.matchers:
            points = score(matcher)
            if points >= threshold:
                matches.append((TYPE_RANK.get(str(record.get("type")), 3), -points, record))
        matches.sort(key=lambda item: item[:2])
        return [describe(record, brief=True) for *_, record in matches[:limit]]

    def match_process(self, properties: dict[str, Any], limit: int = 3) -> list[str]:
        """Detections whose process conditions fit a process entity."""
        return self.match_entity("windows_process", properties, limit)


def describe(record: dict[str, Any], brief: bool = False) -> str:
    """Render one record for the model."""
    if "body" in record:
        return f"# {record.get('name')}\n{record['body']}"
    mitre = ",".join(record.get("mitre", []))
    head = f"{record.get('name')} [{record.get('type') or record.get('category') or ''}]"
    head += f" {mitre}" if mitre else ""
    false_positives = record.get("known_false_positives") or ""
    if brief:
        return f"{head}; known false positives: {false_positives[:200] or 'none listed'}"
    parts = [
        head,
        f"what it detects: {(record.get('description') or record.get('narrative') or '')[:400]}",
    ]
    if record.get("conditions"):
        parts.append("conditions: " + " | ".join(record["conditions"][:4])[:300])
    elif record.get("pseudocode"):
        parts.append(f"logic: {record['pseudocode'][:300]}")
    if false_positives:
        parts.append(f"known false positives: {false_positives[:300]}")
    return "\n".join(parts)


@cache
def default_knowledge(ranker: str = "hybrid") -> KnowledgeBase | None:
    """The packaged knowledge base, loaded once per process."""
    return KnowledgeBase.load(ranker=ranker)


def load_guides(directory: Path) -> list[dict[str, Any]]:
    """Read investigation guides: markdown with a `key: value` header between --- lines.

    Header keys: name, description, keywords, `always` (true: offered with every
    alert), `trigger_only` (true: offered only for the alert's own entities),
    `parents` (the process's parent must be one of these image names), and
    comma-separated triggers `processes` (image names), `entity_types` and `signals`
    (signal substrings).
    """
    guides = []
    for path in sorted(directory.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        _, header, body = text.split("---", 2) if text.startswith("---") else ("", "", text)
        record: dict[str, Any] = {"stem": path.stem, "body": body.strip()}
        for line in header.strip().splitlines():
            key, _, value = line.partition(":")
            key, value = key.strip(), value.strip()
            if key in GUIDE_LIST_FIELDS:
                record[key] = [item.strip().lower() for item in value.split(",") if item.strip()]
            elif key:
                record[key] = value
        guides.append(record)
    return guides


def _matcher(conditions: list[str]) -> Matcher:
    """Build a matcher from extracted SPL conditions."""
    names: list[str] = []
    parents: list[str] = []
    fields: dict[str, tuple[list[str], list[tuple[str, ...]]]] = {
        "process": ([], []),
        "script_text": ([], []),
        "registry_values": ([], []),
    }
    registry_paths: list[str] = []
    for condition in conditions:
        parsed = _CONDITION.match(condition)
        if not parsed:
            continue
        field_name, operator, raw = parsed.groups()
        values = tuple(_values(raw))
        if not values:
            continue
        if field_name in {"process_name", "original_file_name"}:
            names.extend(values)
        elif field_name == "parent_process_name":
            parents.extend(values)
        elif field_name == "registry_path":
            registry_paths.extend(values)
        elif field_name in {"process", "script_text", "registry_value_name", "registry_value_data"}:
            key = "registry_values" if field_name.startswith("registry") else field_name
            required, groups = fields[key]
            if operator == "IN":
                groups.append(values)
            else:
                required.extend(values)

    def terms(key: str) -> Terms:
        required, groups = fields[key]
        return Terms(tuple(required), tuple(groups))

    return Matcher(
        tuple(names),
        tuple(parents),
        terms("process"),
        terms("script_text"),
        tuple(registry_paths),
        terms("registry_values"),
    )


def _values(raw: str) -> list[str]:
    """Condition values in lower case, with SPL escaping undone."""
    quoted = _QUOTED.findall(raw)
    values = quoted or [part.strip() for part in raw.strip("() ").split(",")]
    return [
        value.replace("\\\\", "\\").lower()
        for value in values
        if value.strip("* ") and len(value.strip("* ")) > 1
    ]


def _tokens(text: str) -> list[str]:
    """Lower-case alphanumeric words; `wsmprovhost.exe` gives `wsmprovhost` and `exe`."""
    return [token for token in _TOKEN.findall(text.lower()) if len(token) > 1]


def _contains(text: str, term: str) -> bool:
    """Case-insensitive wildcard containment of one SPL term."""
    return _like(text, f"*{term.strip('*')}*")


def _like(value: str, pattern: str) -> bool:
    """SPL-style wildcard match, case-insensitive."""
    return bool(value) and fnmatch.fnmatchcase(value.lower(), pattern.lower())


def _basename(path: str) -> str:
    """Last path component in lower case."""
    return re.split(r"[\\/]", path.strip().strip('"'))[-1].lower() if path else ""
