from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, TypeAlias, cast

JSON: TypeAlias = None | bool | int | float | str | list["JSON"] | dict[str, "JSON"]
Status = Literal["PASS", "FAIL", "ERROR"]
MAX_BYTES = 4_194_304
MAX_NODES = 100_000
MAX_DEPTH = 128


class Invalid(ValueError):
    """Invalid or unsupported input; never a passing check."""


def obj(value: JSON) -> dict[str, JSON]:
    if not isinstance(value, dict):
        raise Invalid("Expected an object")
    assert len(value) <= MAX_NODES, (
        f"Object exceeds 100,000 members; split the input (observed={len(value)})"
    )
    assert all(len(key) <= 4096 for key in value), (
        f"Object key exceeds 4096 characters; shorten it (observed={len(value)})"
    )
    return value


def string(value: JSON) -> str:
    if not isinstance(value, str) or not value:
        raise Invalid("Expected a nonempty string")
    assert len(value) <= 4096, (
        f"Identifier or path exceeds 4096 characters; shorten it (observed={len(value)})"
    )
    assert "\x00" not in value, "Identifier or path contains NUL; remove it"
    return value


def unique(pairs: list[tuple[str, JSON]]) -> dict[str, JSON]:
    assert len(pairs) <= MAX_NODES, (
        f"Object exceeds the member budget; split the input (observed={len(pairs)})"
    )
    assert sum((len(key) for key, _ in pairs)) <= MAX_BYTES, (
        f"Object keys exceed the input budget (observed={len(pairs)})"
    )
    result: dict[str, JSON] = {}
    for key, value in pairs:
        if key in result:
            raise Invalid(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def decode(text: str) -> JSON:
    assert len(text) <= MAX_BYTES, (
        f"JSON exceeds 4 MiB; split the input (observed={len(text)})"
    )
    value = cast(JSON, json.loads(text, object_pairs_hook=unique))
    canonical = json.dumps(value, allow_nan=False)
    assert len(canonical) <= MAX_BYTES * 6, (
        f"Decoded JSON exceeds the escaped output budget (observed={len(canonical)})"
    )
    return value


def read(path: Path) -> JSON:
    target = path.resolve(strict=True)
    assert target.is_file(), f"JSON input is not a regular file: {target}"
    assert target.stat().st_size <= MAX_BYTES, f"JSON file exceeds 4 MiB: {target}"
    return decode(target.read_text(encoding="utf-8"))


def digest(path: Path) -> str:
    target = path.resolve(strict=True)
    assert target.is_file(), f"Hash input is not a regular file: {target}"
    assert target.stat().st_size <= 64 * MAX_BYTES, (
        f"Hash input exceeds 256 MiB: {target}"
    )
    with target.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def local(root: Path, name: str) -> Path:
    assert root.is_absolute(), f"Repository root must be absolute: {root}"
    assert len(name) <= 4096, (
        f"Repository path exceeds 4096 characters; shorten it (observed={len(name)})"
    )
    rel = Path(name)
    if rel.is_absolute() or ".." in rel.parts:
        raise Invalid(f"Expected a repository-relative path: {name}")
    result = (root / rel).resolve()
    if not result.is_relative_to(root.resolve()):
        raise Invalid(f"Path escapes repository: {name}")
    return result


def tokens(pointer: str) -> list[str]:
    assert len(pointer) <= 4096, (
        f"JSON pointer exceeds 4096 characters; shorten it (observed={len(pointer)})"
    )
    assert pointer.count("/") <= MAX_DEPTH, (
        f"JSON pointer exceeds 128 levels; flatten the document (observed={len(pointer)})"
    )
    if pointer == "":
        return []
    if not pointer.startswith("/") or re.search(r"~(?![01])", pointer):
        raise Invalid("Invalid RFC 6901 pointer")
    return [t.replace("~1", "/").replace("~0", "~") for t in pointer[1:].split("/")]


def resolve(value: JSON, pointer: str) -> JSON:
    parts = tokens(pointer)
    assert len(parts) <= MAX_DEPTH, (
        f"Pointer exceeds the traversal depth budget (observed={len(parts)})"
    )
    assert all(len(part) <= 4096 for part in parts), (
        f"Pointer token exceeds the key budget (observed={len(parts)})"
    )
    for token in parts:
        if isinstance(value, dict):
            if token not in value:
                raise Invalid(f"JSON pointer does not exist: {pointer}")
            value = value[token]
        elif isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]*", token):
            index = int(token)
            if index >= len(value):
                raise Invalid(f"JSON array index out of bounds: {pointer}")
            value = value[index]
        else:
            raise Invalid(f"JSON pointer cannot be resolved: {pointer}")
    return value


def equal(a: JSON, b: JSON) -> bool:
    pending: list[tuple[JSON, JSON, int]] = [(a, b, 0)]
    for _ in range(MAX_NODES):
        if not pending:
            return True
        assert len(pending) <= MAX_NODES, (
            f"Comparison exceeds 100,000 nodes; split the input (observed={len(pending)})"
        )
        left, right, depth = pending.pop()
        assert depth <= MAX_DEPTH, (
            f"Comparison exceeds 128 levels; flatten the input (observed={depth})"
        )
        if isinstance(left, dict) and isinstance(right, dict):
            if left.keys() != right.keys():
                return False
            pending.extend((left[k], right[k], depth + 1) for k in left)
        elif isinstance(left, list) and isinstance(right, list):
            if len(left) != len(right):
                return False
            pending.extend((x, y, depth + 1) for x, y in zip(left, right))
        elif bool in (type(left), type(right)):
            if type(left) is not type(right) or left != right:
                return False
        elif left != right:
            return False
    raise Invalid("Comparison exceeds 100,000 nodes; split the input")


# Accepted field sets per check kind. Records are append-only, so a superseded
# shape (such as the single-event claude_hook) must keep parsing forever.
FIELDS: dict[str, tuple[set[str], ...]] = {
    "json_equals": ({"path", "pointer", "expected"},),
    "file_sha256": ({"path", "sha256"},),
    "path_exists": ({"path"},),
    "claude_hook": ({"events"}, {"event"}),
    "hdr_hooks": ({"harnesses", "events"},),
    "tool_denied": ({"tools"},),
    "append_only": ({"path"},),
}
EVENTS = ("SessionStart", "PreToolUse", "PostToolUse", "Stop")
HARNESSES = ("claude", "codex", "opencode", "pi")
HOOK_KINDS = ("claude_hook", "hdr_hooks")
RECORD_FIELDS = {"schema_version", "id", "title", "rationale", "check"}
DECISION_FIELDS = {"schema_version", "id", "history"}
ENTRY_FIELDS = {"title", "rationale", "check"}
RETIRED_FIELDS = {"status", "rationale"}
DECISIONS = ".hdr/decisions"


def hook_targets(check: dict[str, JSON]) -> tuple[list[str], list[str]]:
    """Harnesses and events a validated hook check covers, in any record shape."""
    assert check.get("kind") in HOOK_KINDS, f"Not a hook check: {check}"
    events = check["events"] if "events" in check else [check["event"]]
    harnesses = check.get("harnesses", ["claude"])
    assert isinstance(events, list) and isinstance(harnesses, list), (
        f"Hook targets were not validated: {check}"
    )
    return [string(h) for h in harnesses], [string(e) for e in events]


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    rationale: str
    kind: str
    check: dict[str, JSON]
    source: str
    supersedes: tuple[str, ...] = ()
    # Every entry in the decision's own log, oldest first; the rule is the last live one.
    history: tuple[dict[str, JSON], ...] = ()
    retired: bool = False


@dataclass(frozen=True)
class Finding:
    id: str
    status: Status
    message: str
    source: str
    paths: tuple[str, ...] = ()

    def data(self) -> dict[str, JSON]:
        assert self.id, "Finding requires a decision or diagnostic identifier"
        assert self.status in ("PASS", "FAIL", "ERROR"), (
            f"Invalid finding status: {self.status}"
        )
        return {
            "id": self.id,
            "status": self.status,
            "message": self.message,
            "source": self.source,
            "paths": list(self.paths),
        }


def parse_rule(root: Path, path: Path) -> Rule:
    assert root.is_absolute(), f"Repository root must be absolute: {root}"
    assert path.is_relative_to(root), f"Decision must be inside repository: {path}"
    local(root, str(path.relative_to(root)))
    return parse_record(root, obj(read(path)), str(path.relative_to(root)))


def parse_record(root: Path, data: dict[str, JSON], source: str) -> Rule:
    """Parse a decision file: a schema 2 history, or a schema 1 single record."""
    assert root.is_absolute(), f"Repository root must be absolute: {root}"
    assert not Path(source).is_absolute(), f"Record source must be relative: {source}"
    version = data.get("schema_version")
    if version == 2 and type(version) is int:
        return parse_history(root, data, source)
    if not RECORD_FIELDS <= set(data) <= RECORD_FIELDS | {"supersedes"}:
        raise Invalid(f"{Path(source).name}: missing or unknown record fields")
    if type(version) is not int or version != 1:
        raise Invalid(
            "Unsupported schema_version; use integer 2 (or 1 for old records)"
        )
    rid = string(data["id"])
    if not re.fullmatch(r"HDR-[0-9]{3,}", rid):
        raise Invalid(
            f"Invalid decision ID: {rid}; use HDR followed by at least three digits"
        )
    check = obj(data["check"])
    kind = string(check.get("kind"))
    if kind not in FIELDS or set(check) - {"kind"} not in FIELDS[kind]:
        raise Invalid(f"{rid}: unsupported check or missing/unknown check fields")
    validate_check(root, kind, check)
    supersedes = parse_supersedes(rid, data)
    entry = {k: data[k] for k in ("title", "rationale", "check")}
    return Rule(
        rid,
        string(data["title"]),
        string(data["rationale"]),
        kind,
        check,
        source,
        tuple(supersedes),
        (entry,),
    )


def parse_supersedes(rid: str, data: dict[str, JSON]) -> list[str]:
    """The legacy schema 1 cross-record retirement list."""
    assert rid, "Supersedes belongs to a decision"
    listed = data.get("supersedes", [])
    if not isinstance(listed, list) or ("supersedes" in data and not listed):
        raise Invalid(f"{rid}: supersedes must be a nonempty list of decision IDs")
    result = [
        s for s in listed if isinstance(s, str) and re.fullmatch(r"HDR-[0-9]{3,}", s)
    ]
    if len(result) != len(listed):
        raise Invalid(f"{rid}: supersedes must be a nonempty list of decision IDs")
    if rid in result:
        raise Invalid(f"{rid}: a record cannot supersede itself")
    assert len(result) == len(listed), f"{rid}: lost superseded IDs: {listed}"
    return result


def parse_entry(root: Path, rid: str, value: JSON) -> dict[str, JSON]:
    """Validate one history entry: a live decision or a retirement."""
    assert rid, "History entries belong to a decision"
    entry = obj(value)
    date = entry.get("date")
    if date is not None and not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}", string(date)
    ):
        raise Invalid(f"{rid}: entry date must be YYYY-MM-DD (observed={date})")
    fields = set(entry) - {"date"}
    if fields == RETIRED_FIELDS:
        if entry["status"] != "retired":
            raise Invalid(
                f'{rid}: status must be "retired" (observed={entry["status"]})'
            )
        string(entry["rationale"])
        return entry
    if fields != ENTRY_FIELDS:
        raise Invalid(
            f"{rid}: each entry needs title, rationale and check, or status and "
            f"rationale (observed={sorted(fields)})"
        )
    string(entry["title"])
    string(entry["rationale"])
    check = obj(entry["check"])
    kind = string(check.get("kind"))
    if kind not in FIELDS or set(check) - {"kind"} not in FIELDS[kind]:
        raise Invalid(f"{rid}: unsupported check or missing/unknown check fields")
    validate_check(root, kind, check)
    assert "title" in entry, f"{rid}: live entry lost its title"
    return entry


def parse_history(root: Path, data: dict[str, JSON], source: str) -> Rule:
    """A schema 2 decision: its own append-only history, newest entry last."""
    assert data.get("schema_version") == 2, f"Not a history record: {source}"
    if set(data) != DECISION_FIELDS:
        raise Invalid(
            f"{Path(source).name}: needs exactly schema_version, id and history"
        )
    rid = string(data["id"])
    if not re.fullmatch(r"HDR-[0-9]{3,}", rid):
        raise Invalid(
            f"Invalid decision ID: {rid}; use HDR followed by at least three digits"
        )
    listed = data["history"]
    if not isinstance(listed, list) or not listed or len(listed) > 1000:
        raise Invalid(f"{rid}: history must list between 1 and 1000 entries")
    history = [parse_entry(root, rid, value) for value in listed]
    live = [e for e in history if "title" in e]
    if "title" not in history[0]:
        raise Invalid(f"{rid}: history must start with a decision, not a retirement")
    current, last = live[-1], history[-1]
    check = obj(current["check"])
    rule = Rule(
        rid,
        string(current["title"]),
        string(last["rationale"]),
        string(check["kind"]),
        check,
        source,
        history=tuple(history),
        retired="status" in last,
    )
    assert rule.history, f"{rid}: parsed an empty history"
    return rule


def entries(data: dict[str, JSON]) -> list[JSON]:
    """A decision file's history entries; a schema 1 record is a one-entry history."""
    assert "id" in data, f"Not a decision record: {sorted(data)}"
    if "history" in data:
        listed = data["history"]
        assert isinstance(listed, list), f"History must be a list: {data['id']}"
        return listed
    result: list[JSON] = [{k: data[k] for k in ENTRY_FIELDS if k in data}]
    assert len(result) == 1, f"Single records hold one entry: {data['id']}"
    return result


def same_entry(old: JSON, new: JSON) -> bool:
    """Equal entries; converting a dateless schema 1 record may add only a date."""
    assert old is not None and new is not None, "Compare two history entries"
    if not isinstance(old, dict) or not isinstance(new, dict):
        return False
    trimmed = {k: v for k, v in new.items() if k in old or k != "date"}
    result = equal(old, trimmed)
    assert isinstance(result, bool), f"Entry comparison failed: {old}"
    return result


def validate_hooks(check: dict[str, JSON]) -> None:
    assert check.get("kind") in HOOK_KINDS, f"Not a hook check: {check}"
    targets = [
        ("events", check.get("events", [check.get("event")]), EVENTS),
        ("harnesses", check.get("harnesses", ["claude"]), HARNESSES),
    ]
    for name, values, allowed in targets:
        if (
            not isinstance(values, list)
            or not values
            or not all(v in allowed for v in values)
            or len(set(map(str, values))) != len(values)
        ):
            raise Invalid(
                f"Unsupported hook {name} {values}; list distinct values from "
                f"{', '.join(allowed)}"
            )
    assert len(targets) == 2, f"Hook checks name events and harnesses: {targets}"


def validate_check(root: Path, kind: str, check: dict[str, JSON]) -> None:
    assert kind in FIELDS, f"Check kind was not validated: {kind}"
    assert root.is_absolute(), f"Repository root must be absolute: {root}"
    if "path" in check:
        local(root, string(check["path"]))
    if kind == "json_equals":
        pointer = check["pointer"]
        if not isinstance(pointer, str):
            raise Invalid("pointer must be a string; use an RFC 6901 pointer")
        tokens(pointer)
    if kind == "file_sha256" and not re.fullmatch(
        r"[0-9a-f]{64}", string(check["sha256"])
    ):
        raise Invalid("sha256 must be 64 lowercase hexadecimal characters")
    if kind in HOOK_KINDS:
        validate_hooks(check)
    if kind == "tool_denied":
        names = check["tools"]
        if (
            not isinstance(names, list)
            or not names
            or not all(isinstance(n, str) and n for n in names)
        ):
            raise Invalid("tools must be a nonempty list of exact tool names")


def load(root: Path) -> list[Rule]:
    """Current decisions: the latest entry of every decision still in force."""
    assert root.is_absolute(), f"Repository root must be absolute: {root}"
    rules = records(root)
    ids = {r.id for r in rules}
    superseded = {s for r in rules for s in r.supersedes}
    if not superseded <= ids:
        raise Invalid(f"Superseded decision does not exist: {min(superseded - ids)}")
    current = [r for r in rules if r.id not in superseded and not r.retired]
    assert len(current) <= len(rules) - len(superseded), (
        f"Current count mismatch (records={len(rules)}, superseded={len(superseded)})"
    )
    return current


def snapshot(root: Path, names: list[str]) -> dict[str, str]:
    """Digest every file under each repository-relative path."""
    assert root.is_absolute(), f"Snapshot root must be absolute: {root}"
    result: dict[str, str] = {}
    for name in names:
        target = local(root, name)
        files = (
            [target]
            if target.is_file()
            else sorted(p for p in target.rglob("*") if p.is_file())
        )
        assert len(files) <= 4096, (
            f"Protected path holds more than 4096 files (observed={len(files)})"
        )
        for path in files:
            result[str(path.relative_to(root))] = digest(path)
    return result


def records(root: Path) -> list[Rule]:
    """Every record in the log, including superseded ones."""
    assert root.is_absolute(), f"Repository root must be absolute: {root}"
    directory = local(root, DECISIONS)
    paths = sorted(directory.glob("*.json"))
    if not paths:
        raise Invalid("No HDR records in .hdr/decisions/*.json; run hdr init")
    assert len(paths) <= 1024, (
        f"More than 1024 records; split the governance scope (observed={len(paths)})"
    )
    rules = [parse_rule(root, path) for path in paths]
    seen: set[str] = set()
    for rule in rules:
        if rule.id in seen:
            raise Invalid(f"Duplicate decision ID: {rule.id}; assign distinct IDs")
        seen.add(rule.id)
    return rules


def evaluate(root: Path, rule: Rule) -> Finding:
    path = string(rule.check["path"])
    try:
        target = local(root, path)
        if rule.kind == "path_exists":
            ok = target.exists()
        elif rule.kind == "file_sha256":
            ok = digest(target) == rule.check["sha256"]
        else:
            assert rule.kind == "json_equals", f"Unsupported state checker: {rule.kind}"
            pointer = rule.check["pointer"]
            assert isinstance(pointer, str), (
                f"Validated pointer must be a string (observed={type(pointer).__name__})"
            )
            ok = equal(resolve(read(target), pointer), rule.check["expected"])
        return Finding(
            rule.id, "PASS" if ok else "FAIL", rule.title, rule.source, (path,)
        )
    except (OSError, ValueError, AssertionError, RecursionError) as exc:
        return Finding(rule.id, "ERROR", f"{rule.title}: {exc}", rule.source, (path,))
