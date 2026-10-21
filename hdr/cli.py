from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import uuid
import webbrowser
from datetime import UTC, datetime
from pathlib import Path

from hdr import __version__
from hdr.claude import inspect
from hdr.core import (
    DECISIONS,
    EVENTS,
    HARNESSES,
    HOOK_KINDS,
    JSON,
    Finding,
    Invalid,
    Rule,
    decode,
    digest,
    entries,
    evaluate,
    load,
    local,
    obj,
    parse_record,
    read,
    records,
    same_entry,
    snapshot,
    string,
)
from hdr.explain import render
from hdr.harnesses import NEXT_STEP, check_hooks, install, operations

DISCLAIMER = (
    "Scope: repository state and observed settings files only. Managed policy, launch flags, "
    "plugin hooks, sandboxing and live configuration are not attested."
)
GRAIN = (
    "Adding an HDR: one decision per record, phrased as the outcome a human would "
    "state. Group checks that share one rationale (one record for every hook event, "
    "not one per event); split only when the parts could be retired independently. "
    "Never edit a record; append a new one, and ask a human to supersede."
)


def discover(start: Path) -> Path | None:
    assert start.is_absolute(), f"Discovery requires an absolute path: {start}"
    assert start.is_dir(), f"Discovery directory does not exist: {start}"
    start = start.resolve()
    for path in (start, *start.parents):
        if (path / ".hdr").is_dir():
            return path
        if (path / ".git").exists():
            break
    return None


def git(root: Path, args: list[str]) -> str | None:
    assert root.is_dir(), f"Git repository directory is missing: {root}"
    assert args, "Git operation is missing; provide explicit arguments"
    try:
        p = subprocess.run(
            ["git", "-C", str(root), *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return p.stdout.strip() if p.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def policy_hash(root: Path) -> str:
    assert root.is_absolute(), f"Policy root must be absolute: {root}"
    assert root.is_dir(), f"Policy root does not exist: {root}"
    entries = [(r.source, digest(local(root, r.source))) for r in records(root)]
    return hashlib.sha256(json.dumps(entries).encode()).hexdigest()


def checks(root: Path, tool: str | None = None) -> tuple[list[Finding], list[Rule]]:
    assert root.is_absolute(), f"Check root must be absolute: {root}"
    rules = load(root)
    layers, findings = inspect(root)
    for rule in rules:
        if rule.kind in HOOK_KINDS:
            findings.append(check_hooks(root, rule, layers))
        elif rule.kind == "tool_denied":
            names = rule.check["tools"]
            assert isinstance(names, list), f"Tool names were not validated: {rule.id}"
            if tool is not None:
                findings.append(
                    Finding(
                        rule.id,
                        "FAIL" if tool in names else "PASS",
                        f"{rule.title}: tool={tool}",
                        rule.source,
                    )
                )
        elif rule.kind == "append_only":
            continue  # Needs a session baseline; evaluated by hook_checks.
        else:
            findings.append(evaluate(root, rule))
    return findings, rules


def failed(findings: list[Finding]) -> bool:
    assert len(findings) <= 4096, (
        f"Finding count exceeds the report budget (observed={len(findings)})"
    )
    assert all(f.status in ("PASS", "FAIL", "ERROR") for f in findings), (
        f"Invalid finding status (observed={len(findings)})"
    )
    return any(f.status != "PASS" for f in findings)


def summary(findings: list[Finding]) -> str:
    assert len(findings) <= 4096, (
        f"Finding count exceeds the display budget (observed={len(findings)})"
    )
    assert all(f.id for f in findings), (
        f"Every displayed finding needs an identifier (observed={len(findings)})"
    )
    return "\n".join(f"{f.status:5} {f.id:15} {f.message}" for f in findings)


def report(
    root: Path,
    findings: list[Finding],
    rules: list[Rule],
    event: dict[str, JSON] | None = None,
) -> dict[str, JSON]:
    assert root.is_absolute(), f"Report root must be absolute: {root}"
    assert len(rules) <= 1024, (
        f"Report contains more than 1024 decision records (observed={len(rules)})"
    )
    layers, _ = inspect(root)
    evidence: dict[str, JSON] = {}
    paths = {r.source for r in rules} | {p for f in findings for p in f.paths}
    for name in sorted(paths):
        path = Path(name) if Path(name).is_absolute() else root / name
        try:
            evidence[name] = (
                {"sha256": digest(path)} if path.is_file() else {"missing": True}
            )
        except OSError:
            evidence[name] = {"unreadable": True}
    config: list[JSON] = [
        {"path": str(layer.path), "sha256": layer.sha256} for layer in layers
    ]
    return {
        "schema_version": 1,
        "run_id": uuid.uuid4().hex,
        "hdr_version": __version__,
        "timestamp": datetime.now(UTC).isoformat(),
        "root": str(root),
        "scope": DISCLAIMER,
        "passed": not failed(findings),
        "findings": [f.data() for f in findings],
        "action_rules": [
            r.id for r in rules if r.kind in ("tool_denied", "append_only")
        ],
        "git_head": git(root, ["rev-parse", "HEAD"]),
        "git_status": git(root, ["status", "--porcelain"]),
        "policy_sha256": policy_hash(root),
        "evidence": evidence,
        "config_sources": config,
        # No tool inputs, prompts, transcripts, file contents or environment variables.
        "event": {
            key: value
            for key, value in (event or {}).items()
            if key
            in {"hook_event_name", "session_id", "tool_name", "tool_use_id", "harness"}
        },
    }


def save(root: Path, data: dict[str, JSON]) -> Path:
    assert root.is_absolute(), f"Run root must be absolute: {root}"
    assert re.fullmatch(r"[a-f0-9]{32}", string(data.get("run_id"))), (
        "Run identifier must be 32 hexadecimal characters"
    )
    directory = local(root, ".hdr/runs")
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (string(data["run_id"]) + ".json")
    with path.open("x", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2)
        stream.write("\n")
    return path


def session_key(event: dict[str, JSON]) -> str:
    """Baseline key; Claude keeps the bare session ID that earlier versions used."""
    session, harness = string(event.get("session_id")), event.get("harness", "claude")
    assert harness in HARNESSES, f"Unknown harness: {harness}"
    key = session if harness == "claude" else f"{harness}:{session}"
    assert key.endswith(session), f"Baseline key lost its session: {key}"
    return key


def session_path(session: str) -> Path:
    assert session, "Session ID is missing; restart the harness"
    base = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state")))
    assert base.is_absolute(), f"XDG_STATE_HOME must be absolute: {base}"
    return (
        base / "hdr/sessions" / (hashlib.sha256(session.encode()).hexdigest() + ".json")
    )


def protected(rules: list[Rule]) -> list[str]:
    """The decision log plus every path an active append_only rule names."""
    assert len(rules) <= 1024, f"Too many active rules (observed={len(rules)})"
    names = {string(r.check["path"]) for r in rules if r.kind == "append_only"}
    result = sorted(names | {DECISIONS})
    assert not any(Path(n).is_absolute() for n in result), f"Absolute path: {result}"
    return result


def attempted(root: Path, rule: Rule, event: dict[str, JSON]) -> str | None:
    """Why a PreToolUse file edit would break an append-only path, if it would."""
    assert root.is_absolute(), f"Repository root must be absolute: {root}"
    assert rule.kind == "append_only", f"Expected an append-only rule: {rule.id}"
    directory = local(root, string(rule.check["path"]))
    cwd = Path(string(event.get("cwd")))
    for kind, target, content in operations(string(event.get("harness")), event):
        path = (cwd / target).resolve()
        if path == directory or path.is_relative_to(directory):
            reason = violation(root, directory, (kind, path, content))
            if reason:
                return f"{event.get('tool_name')} {reason}"
    return None


def violation(
    root: Path, directory: Path, operation: tuple[str, Path, str | None]
) -> str | None:
    """Why one normalised file operation breaks an append-only directory."""
    kind, path, content = operation
    assert kind in ("Write", "Edit"), f"Unnormalised file operation: {kind}"
    assert path.is_absolute(), f"Operation path must be resolved: {path}"
    decisions = directory == local(root, DECISIONS)
    if kind != "Write" or path.exists():
        if decisions:
            return (
                f"would change {path.name}; only a person may add to a decision's "
                "history, so ask the user"
            )
        return f"would alter {path.name}; files here can only be added"
    if not decisions:
        return None
    try:
        source = str(path.relative_to(root))
        record = parse_record(root, obj(decode(string(content))), source)
    except (ValueError, AssertionError) as exc:
        return f"would add an invalid decision: {exc}"
    if record.id in {r.id for r in records(root)}:
        return f"{record.id} already exists; use the next free ID"
    if record.supersedes or len(record.history) > 1:
        return (
            "a new decision starts with one entry and supersedes nothing; ask the user"
        )
    return None


def history_of(root: Path, name: str) -> list[JSON] | None:
    """History entries of a decision file, or None for any other protected file."""
    assert not Path(name).is_absolute(), f"Protected path must be relative: {name}"
    path = local(root, name)
    if not name.startswith(DECISIONS + "/") or not path.is_file():
        return None
    try:
        result = entries(obj(read(path)))
    except (ValueError, AssertionError):
        return None
    assert isinstance(result, list), f"History must be a list: {name}"
    return result


def extends(old: JSON, new: list[JSON] | None) -> bool:
    """True when new keeps every old entry, unchanged and in order, and only adds."""
    assert new is None or isinstance(new, list), f"Unexpected history: {new}"
    if not isinstance(old, list) or new is None or len(new) < len(old):
        return False
    result = all(same_entry(o, n) for o, n in zip(old, new))
    assert not result or len(new) >= len(old), (
        f"History shrank: {len(old)} -> {len(new)}"
    )
    return result


def accepted(
    root: Path, rules: list[Rule], baseline: dict[str, JSON]
) -> tuple[dict[str, JSON], dict[str, JSON]]:
    """Pinned digests and histories, moved forward past new files and valid appends."""
    assert root.is_absolute(), f"Baseline root must be absolute: {root}"
    digests = dict(obj(baseline.get("records", {})))
    histories = dict(obj(baseline.get("history", {})))
    for path, sha in snapshot(root, protected(rules)).items():
        now = history_of(root, path)
        if path not in digests or (
            digests[path] != sha and extends(histories.get(path), now)
        ):
            digests[path] = sha
            if now is not None:
                histories[path] = now
    pinned = len(obj(baseline.get("records", {})))
    assert len(digests) >= pinned, f"Baseline shrank ({pinned} -> {len(digests)})"
    return digests, histories


def changes(name: str, before: dict[str, JSON], after: dict[str, str]) -> list[str]:
    assert not Path(name).is_absolute(), f"Protected path must be relative: {name}"
    prefix = Path(name)
    result: list[str] = []
    for path, sha in sorted(before.items()):
        if Path(path) != prefix and not Path(path).is_relative_to(prefix):
            continue
        if path not in after:
            result.append(f"removed {path}")
        elif after[path] != sha:
            result.append(f"changed {path}")
    assert len(result) <= len(before), (
        f"More changes than pinned files (observed={len(result)}, pinned={len(before)})"
    )
    return result


def integrity(
    root: Path, rules: list[Rule], baseline: dict[str, JSON]
) -> list[Finding]:
    """Compare protected files with the session baseline; appends are allowed."""
    assert root.is_absolute(), f"Integrity root must be absolute: {root}"
    assert len(rules) <= 1024, f"Too many active rules (observed={len(rules)})"
    if "records" not in baseline:
        # Baselines from before per-file pinning hold one aggregate hash.
        if baseline.get("policy_sha256") == policy_hash(root):
            return []
        return [
            Finding(
                "POLICY-DRIFT",
                "FAIL",
                "HDR records changed during the session; review and restart",
                DECISIONS,
            )
        ]
    before, _ = accepted(root, rules, baseline)
    after = snapshot(root, protected(rules))
    guards = [
        (r.id, r.title, string(r.check["path"]), r.source)
        for r in rules
        if r.kind == "append_only"
    ]
    if not any(Path(DECISIONS).is_relative_to(path) for _, _, path, _ in guards):
        guards.append(
            ("LOG-INTEGRITY", "Decision records are append-only", DECISIONS, DECISIONS)
        )
    findings: list[Finding] = []
    for rid, title, path, source in guards:
        found = changes(path, before, after)
        findings.append(
            Finding(
                rid,
                "FAIL" if found else "PASS",
                f"{title}: {'; '.join(found)}; history may only grow, so restore it"
                if found
                else title,
                source,
                tuple(f.split(" ", 1)[1] for f in found),
            )
        )
    return findings


def pin(
    event: dict[str, JSON], root: Path, rules: list[Rule], findings: list[Finding]
) -> None:
    """Record new files and valid appends in the baseline; nothing else moves."""
    assert root.is_absolute(), f"Baseline root must be absolute: {root}"
    if any(f.id == "POLICY-DRIFT" for f in findings):
        return
    session = session_path(session_key(event))
    baseline = obj(read(session)) if session.exists() else {}
    digests, histories = accepted(root, rules, baseline)
    if digests != baseline.get("records") or histories != baseline.get("history"):
        session.parent.mkdir(parents=True, exist_ok=True)
        data = {"root": str(root), "records": digests, "history": histories}
        session.write_text(json.dumps(data))
    assert session.exists(), f"Session baseline was not written: {session}"


def hook_checks(
    root: Path, event: dict[str, JSON], baseline: dict[str, JSON] | None
) -> tuple[list[Finding], list[Rule]]:
    assert root.is_dir(), f"Hook repository is missing: {root}"
    kind = string(event["hook_event_name"])
    assert kind in EVENTS, f"Unsupported hook event: {kind}"
    findings, rules = checks(
        root, string(event.get("tool_name")) if kind == "PreToolUse" else None
    )
    if kind == "PreToolUse":
        for rule in rules:
            reason = (
                attempted(root, rule, event) if rule.kind == "append_only" else None
            )
            if reason:
                findings.append(
                    Finding(rule.id, "FAIL", f"{rule.title}: {reason}", rule.source)
                )
        action_ids = {
            r.id for r in rules if r.kind in (*HOOK_KINDS, "tool_denied", "append_only")
        }
        findings = [
            f for f in findings if f.id in action_ids or f.id.startswith("CONFIG-")
        ]
        if baseline is None:
            findings.append(
                Finding(
                    "SESSION",
                    "ERROR",
                    "No SessionStart baseline; restart Claude",
                    "session",
                )
            )
    if baseline is not None:
        findings.extend(integrity(root, rules, baseline))
    if event.get("permission_mode") == "bypassPermissions":
        findings.append(
            Finding(
                "SESSION-MODE", "FAIL", "Hook reports bypassPermissions", "hook payload"
            )
        )
    return findings, rules


def hook_response(
    event: dict[str, JSON], data: dict[str, JSON], findings: list[Finding]
) -> dict[str, JSON]:
    kind = string(event["hook_event_name"])
    assert kind in EVENTS, f"Unsupported hook response: {kind}"
    assert data.get("run_id"), "Hook response requires a recorded run identifier"
    has_failures = failed(findings)
    message = "HDR " + ("FAILED" if has_failures else "PASS") + "\n" + summary(findings)
    message += "\nRun: " + string(data["run_id"])
    if kind == "SessionStart":
        return {
            "systemMessage": message + "\n" + DISCLAIMER,
            "hookSpecificOutput": {
                "hookEventName": kind,
                "additionalContext": message + "\n" + GRAIN,
            },
        }
    if kind == "PreToolUse" and has_failures:
        return {
            "hookSpecificOutput": {
                "hookEventName": kind,
                "permissionDecision": "deny",
                "permissionDecisionReason": message,
            }
        }
    if kind in ("PostToolUse", "Stop") and has_failures:
        if kind == "Stop" and event.get("stop_hook_active") is True:
            return {
                "systemMessage": message
                + "\nRepeated Stop check: returning control to the user."
            }
        return {"decision": "block", "reason": message}
    return {}


def handle_event(event: dict[str, JSON]) -> dict[str, JSON]:
    """Check one hook event; event["harness"] names the adapter that sent it."""
    kind = string(event.get("hook_event_name"))
    assert event.get("harness") in HARNESSES, f"Unknown harness: {event.get('harness')}"
    if kind not in EVENTS:
        raise Invalid(f"Unsupported hook event: {kind}; reinstall the HDR hooks")
    cwd = Path(string(event.get("cwd"))).resolve()
    assert cwd.is_dir(), f"Hook working directory does not exist: {cwd}"
    session = session_path(session_key(event))
    # Resume and compaction fire SessionStart again; keep the original baseline.
    baseline = obj(read(session)) if session.exists() else None
    root = Path(string(baseline["root"])) if baseline else discover(cwd)
    if root is None:
        return {}
    if not cwd.is_relative_to(root):
        raise Invalid(
            "Session moved outside the governed repository; start a new session there"
        )
    assert root.is_absolute(), f"Session baseline root must be absolute: {root}"
    findings, rules = hook_checks(root, event, baseline)
    if baseline is not None or kind == "SessionStart":
        pin(event, root, rules, findings)
    data = report(root, findings, rules, event)
    save(root, data)
    return hook_response(event, data, findings)


def hook(harness: str) -> int:
    try:
        text = sys.stdin.read(1_048_577)
        assert len(text) <= 1048576, (
            f"Hook input exceeds 1 MiB; reduce the event payload (observed={len(text)})"
        )
        event = obj(decode(text))
        assert "hook_event_name" in event, (
            "Hook input has no event name; reinstall the integration"
        )
        print(json.dumps(handle_event({**event, "harness": harness})))
        return 0
    except (OSError, ValueError, KeyError, AssertionError, RecursionError) as exc:
        print(f"HDR ERROR: {exc}", file=sys.stderr)
        return 2


def seed(root: Path, harnesses: list[str]) -> None:
    assert root.is_absolute(), f"Initialisation root must be absolute: {root}"
    assert root.is_dir(), f"Create the repository directory first: {root}"
    directory = root / DECISIONS
    if (root / ".hdr").exists():
        raise Invalid("Refusing to overwrite an existing .hdr directory")
    directory.mkdir(parents=True)
    (root / ".hdr/.gitignore").write_text("runs/\n")
    today = datetime.now(UTC).date().isoformat()
    seeds: list[tuple[str, str, str, dict[str, JSON]]] = [
        (
            "HDR-001",
            "Decision records are append-only",
            "Agents may add decisions but never change one; a person changes a "
            "decision by appending to its history.",
            {"kind": "append_only", "path": DECISIONS},
        ),
        (
            "HDR-002",
            "Register HDR checks for every lifecycle event",
            "Every supported lifecycle event must reach the deterministic checker.",
            {
                "kind": "hdr_hooks",
                "harnesses": list(harnesses),
                "events": list(EVENTS),
            },
        ),
    ]
    records: list[dict[str, JSON]] = [
        {
            "schema_version": 2,
            "id": rid,
            "history": [
                {"date": today, "title": title, "rationale": why, "check": check}
            ],
        }
        for rid, title, why, check in seeds
    ]
    for record in records:
        (directory / f"{record['id']}.json").write_text(
            json.dumps(record, indent=2) + "\n"
        )


def trace(root: Path, run_id: str, decision: str | None) -> dict[str, JSON]:
    if not re.fullmatch(r"[a-f0-9]{32}", run_id):
        raise Invalid("Expected a 32-character run ID from hdr check")
    data = obj(read(local(root, f".hdr/runs/{run_id}.json")))
    findings = data["findings"]
    assert isinstance(findings, list), (
        f"Saved report findings must be an array (observed={type(findings).__name__})"
    )
    selected = [
        obj(f) for f in findings if decision is None or obj(f)["id"] == decision
    ]
    if decision and not selected:
        raise Invalid("Decision not present in this run")
    paths: set[str] = set()
    for f in selected:
        paths.add(string(f["source"]))
        values = f["paths"]
        assert isinstance(values, list), (
            f"Saved finding paths must be an array (observed={type(values).__name__})"
        )
        paths.update(string(v) for v in values)
    histories: dict[str, JSON] = {}
    head = data.get("git_head")
    for name in sorted(paths):
        path = Path(name)
        if path.is_absolute():
            if not path.is_relative_to(root):
                histories[name] = "External configuration: no repository Git history"
                continue
            name = str(path.relative_to(root))
        if not isinstance(head, str) or not re.fullmatch(r"[0-9a-f]{40,64}", head):
            histories[name] = "No Git HEAD recorded"
            continue
        histories[name] = git(
            root, ["log", "-5", "--format=%h %aI %s", head, "--", name]
        )
    return {
        "recorded_run": data,
        "selected_findings": [item for item in selected],
        "history_at_recorded_head": histories,
        "note": "History is correlation, not proof of agent authorship. Local reports are not tamper-proof.",
    }


def explain(root: Path) -> Path:
    assert root.is_dir(), f"Report repository is missing: {root}"
    findings, rules = checks(root)
    data = report(root, findings, rules)
    layers, _ = inspect(root)
    directory = local(root, ".hdr/runs")
    directory.mkdir(parents=True, exist_ok=True)
    recent = sorted(directory.glob("*.json"), key=lambda p: p.stat().st_mtime)[-20:]
    runs = [obj(read(p)) for p in reversed(recent)]
    path = directory / "report.html"
    path.write_text(render(data, findings, layers, runs), encoding="utf-8")
    assert path.is_file(), f"Report was not written: {path}"
    return path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Deterministic Harness Decision Records"
    )
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("init")
    p.add_argument("--harness", action="append", choices=HARNESSES)
    commands.add_parser("validate")
    for name in ("check", "inspect", "doctor"):
        p = commands.add_parser(name)
        p.add_argument("--json", action="store_true")
    p = commands.add_parser("explain")
    p.add_argument("--no-open", action="store_true")
    p = commands.add_parser("install")
    p.add_argument("harness", choices=HARNESSES)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--user", action="store_true")
    group.add_argument("--project", action="store_true")
    p = commands.add_parser("trace")
    p.add_argument("run_id")
    p.add_argument("--decision")
    p = commands.add_parser("hook")
    p.add_argument("--harness", choices=HARNESSES, default="claude")
    assert commands.choices, "CLI requires registered commands"
    assert "check" in commands.choices, "CLI must expose its compliance check"
    return parser


def main(argv: list[str] | None = None) -> int:
    if sys.flags.optimize:
        print(
            "HDR ERROR: Python optimisation disables contracts; run without -O",
            file=sys.stderr,
        )
        return 2
    args = build_parser().parse_args(argv)
    assert args.command, "CLI command was not parsed"
    assert args.root.is_absolute() or args.root.parts, (
        f"Repository path is empty (observed={args.root})"
    )
    if args.command == "hook":
        return hook(args.harness)
    try:
        root = args.root.resolve()
        if args.command == "init":
            seed(root, args.harness or ["claude"])
            print(
                "Created 2 HDRs. Decision records are append-only. Review before installing."
            )
            return 0
        if args.command == "install":
            print(
                f"Installed hooks: {install(root, args.harness, args.user)}\n"
                f"{NEXT_STEP[args.harness]}; existing settings preserved."
            )
            return 0
        root = discover(root) or root
        if args.command == "validate":
            current, total = len(load(root)), len(records(root))
            print(f"PASS: {current} current decisions ({total} decision files)")
            return 0
        if args.command == "trace":
            print(json.dumps(trace(root, args.run_id, args.decision), indent=2))
            return 0
        if args.command == "explain":
            path = explain(root)
            print(f"Report: {path}")
            if not args.no_open:
                webbrowser.open(path.as_uri())
            return 0
        findings, rules = checks(root)
        data = report(root, findings, rules)
        if args.command == "check":
            save(root, data)
        return display_result(args, data, findings)
    except (OSError, ValueError, KeyError, AssertionError, RecursionError) as exc:
        print(f"HDR ERROR: {exc}", file=sys.stderr)
        return 2


def display_result(
    args: argparse.Namespace, data: dict[str, JSON], findings: list[Finding]
) -> int:
    assert args.command in ("check", "inspect", "doctor"), (
        f"Cannot display command: {args.command}"
    )
    assert data.get("run_id"), "Check result is missing its run identifier"
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print(summary(findings))
        print(f"Action rules: {data['action_rules']} (evaluated on PreToolUse)")
        print(DISCLAIMER)
        if args.command == "check":
            print(f"Run: {data['run_id']}")
        if failed(findings):
            print(
                "Repair: hdr install claude --project; review failed record paths; rerun hdr check."
            )
    if any(f.status == "ERROR" for f in findings):
        return 2
    return 1 if failed(findings) else 0
