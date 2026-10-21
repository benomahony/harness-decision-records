"""Harness adapters: where each harness registers HDR, how to install it, and
how each one names its file-editing tools."""

from __future__ import annotations

import json
import os
from pathlib import Path

from hdr.claude import Layer, command, command_args, config_dir, registered
from hdr.core import (
    EVENTS,
    HARNESSES,
    HOOK_KINDS,
    JSON,
    Finding,
    Invalid,
    Rule,
    hook_targets,
    obj,
    read,
)

SHIMS = Path(__file__).with_name("shims")
NEXT_STEP = {
    "claude": "Restart Claude",
    "codex": "Restart Codex, trust the project and approve the HDR hooks when asked",
    "opencode": "Restart opencode",
    "pi": "Restart pi and trust the project, or run /reload",
}
# Native tool name -> (normalised operation, field holding the target path).
FILE_TOOLS: dict[str, dict[str, tuple[str, str]]] = {
    "claude": {
        "Write": ("Write", "file_path"),
        "Edit": ("Edit", "file_path"),
        "MultiEdit": ("Edit", "file_path"),
        "NotebookEdit": ("Edit", "notebook_path"),
    },
    "codex": {},
    "opencode": {"write": ("Write", "filePath"), "edit": ("Edit", "filePath")},
    "pi": {"write": ("Write", "path"), "edit": ("Edit", "path")},
}
# Codex apply_patch and shell commands use `command`; opencode apply_patch uses `patchText`.
PATCH_FIELDS = ("command", "patchText")
PATCH_MARKERS = {
    "*** Add File: ": "Write",
    "*** Update File: ": "Edit",
    "*** Delete File: ": "Edit",
    "*** Move to: ": "Write",
}


def home(harness: str) -> Path:
    """User-level configuration directory, honouring each harness's override."""
    assert harness in HARNESSES, f"Unsupported harness: {harness}"
    user = Path.home()
    defaults = {
        "claude": ("CLAUDE_CONFIG_DIR", user / ".claude"),
        "codex": ("CODEX_HOME", user / ".codex"),
        "pi": ("PI_CODING_AGENT_DIR", user / ".pi/agent"),
    }
    if harness == "opencode":
        xdg = os.environ.get("XDG_CONFIG_HOME", str(user / ".config"))
        target = Path(xdg).expanduser() / "opencode"
    else:
        variable, default = defaults[harness]
        target = Path(os.environ.get(variable, str(default))).expanduser()
    assert target.is_absolute(), f"{harness} configuration must be absolute: {target}"
    return target.resolve()


def location(root: Path, harness: str, user: bool) -> Path:
    """The file `hdr install <harness>` writes at user or project scope."""
    assert root.is_absolute(), f"Repository root must be absolute: {root}"
    names = {
        "claude": ("settings.json", ".claude/settings.json"),
        "codex": ("hooks.json", ".codex/hooks.json"),
        "opencode": ("plugins/hdr.ts", ".opencode/plugins/hdr.ts"),
        "pi": ("extensions/hdr.ts", ".pi/extensions/hdr.ts"),
    }
    user_name, project_name = names[harness]
    base = config_dir() if harness == "claude" else home(harness)
    result = base / user_name if user else root / project_name
    assert result.is_absolute(), f"Install location must be absolute: {result}"
    return result


def shim(harness: str) -> str:
    """Plugin source for harnesses that load in-process code instead of commands."""
    assert harness in ("opencode", "pi"), f"No plugin shim for {harness}"
    template = (SHIMS / f"{harness}.ts").read_text(encoding="utf-8")
    assert "__HDR_COMMAND__" in template, (
        f"Shim template has no command slot: {harness}"
    )
    return template.replace("__HDR_COMMAND__", json.dumps(command_args(harness)))


def install(root: Path, harness: str, user: bool) -> Path:
    assert root.is_dir(), f"Repository directory is missing: {root}"
    if harness in ("claude", "codex"):
        return install_hooks_file(root, harness, user)
    path = location(root, harness, user)
    if path.is_symlink():
        raise Invalid(f"Refusing to replace a symlinked plugin: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(shim(harness), encoding="utf-8")
    assert path.is_file(), f"Plugin was not written: {path}"
    return path


def install_hooks_file(root: Path, harness: str, user: bool) -> Path:
    """Add the HDR command for every event to a Claude-shaped hooks file."""
    assert harness in ("claude", "codex"), f"Not a JSON hook harness: {harness}"
    path = location(root, harness, user)
    if path.is_symlink():
        raise Invalid("Refusing to replace symlinked settings")
    data = obj(read(path)) if path.exists() else {}
    hooks = obj(data.setdefault("hooks", {}))
    for event in EVENTS:
        groups = hooks.setdefault(event, [])
        if not isinstance(groups, list):
            raise Invalid("Existing hooks must be arrays")
        if not registered([Layer(path, data, None)], event, harness):
            handler: JSON = {
                "type": "command",
                "command": command(harness),
                "timeout": 15,
            }
            groups.append({"matcher": "*", "hooks": [handler]})
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        backup = path.with_name(path.name + ".hdr-backup")
        if not backup.exists():
            backup.write_bytes(path.read_bytes())
    path.write_text(json.dumps(data, indent=2) + "\n")
    assert path.is_file(), f"Hook settings were not written: {path}"
    return path


def sources(root: Path, harness: str, event: str, layers: list[Layer]) -> list[str]:
    """Where the HDR checker is registered for one harness event."""
    assert event in EVENTS, f"Unsupported hook event: {event}"
    if harness == "claude":
        return registered(layers, event)
    paths = [location(root, harness, user) for user in (True, False)]
    if harness == "codex":
        found = [Layer(p, obj(read(p)), None) for p in paths if p.is_file()]
        return registered(found, event, harness)
    # A plugin shim handles every event, so it counts only if it is exactly ours.
    expected = shim(harness)
    result = [
        str(p)
        for p in paths
        if p.is_file() and p.read_text(encoding="utf-8") == expected
    ]
    assert len(result) <= len(paths), f"Duplicate shim sources: {result}"
    return result


def check_hooks(root: Path, rule: Rule, layers: list[Layer]) -> Finding:
    assert rule.kind in HOOK_KINDS, f"Expected a hook decision: {rule.id}"
    harnesses, events = hook_targets(rule.check)
    try:
        missing: list[tuple[str, str]] = []
        found: set[str] = set()
        for harness in harnesses:
            for event in events:
                paths = sources(root, harness, event, layers)
                found.update(paths)
                if not paths:
                    missing.append((harness, event))
    except ValueError as exc:
        return Finding(rule.id, "ERROR", str(exc), rule.source)
    # Single-harness Claude records keep their original wording.
    bare = harnesses == ["claude"]
    if missing:
        fixes = "; ".join(
            f"run hdr install {h} --project"
            for h in dict.fromkeys(h for h, _ in missing)
        )
        names = ", ".join(e if bare else f"{h} {e}" for h, e in missing)
        message = f"{names}: HDR hook missing; {fixes}"
    else:
        names = ", ".join(e if bare else f"{h} {e}" for h in harnesses for e in events)
        message = f"{names}: HDR hook registered on disk"
    status = "FAIL" if missing else "PASS"
    result = Finding(rule.id, status, message, rule.source, tuple(sorted(found)))
    assert result.status == "PASS" or missing, f"Failed without a gap: {rule.id}"
    return result


def patch_operations(text: str) -> list[tuple[str, str, str | None]]:
    """File operations in an apply_patch envelope; added files carry their content."""
    assert "*** Begin Patch" in text, "Not an apply_patch envelope"
    pending: list[tuple[str, str, list[str] | None]] = []
    for line in text.splitlines():
        marker = next((m for m in PATCH_MARKERS if line.startswith(m)), None)
        if marker:
            body: list[str] | None = [] if marker == "*** Add File: " else None
            pending.append((PATCH_MARKERS[marker], line[len(marker) :].strip(), body))
        elif pending and line.startswith("+"):
            added = pending[-1][2]
            if added is not None:
                added.append(line[1:])
    result = [(k, p, None if c is None else "\n".join(c) + "\n") for k, p, c in pending]
    assert all(p for _, p, _ in result), f"Patch names an empty path: {result}"
    return result


def operations(
    harness: str, event: dict[str, JSON]
) -> list[tuple[str, str, str | None]]:
    """Normalise a tool call into (Write|Edit, path, new content) operations."""
    assert harness in HARNESSES, f"Unsupported harness: {harness}"
    tool = event.get("tool_name")
    data = event.get("tool_input", {})
    if not isinstance(tool, str) or not isinstance(data, dict):
        return []
    if tool in FILE_TOOLS[harness]:
        kind, field = FILE_TOOLS[harness][tool]
        target, content = data.get(field), data.get("content")
        if not isinstance(target, str) or not target:
            return []
        return [(kind, target, content if isinstance(content, str) else None)]
    texts = [data.get(f) for f in PATCH_FIELDS]
    patches = [t for t in texts if isinstance(t, str) and "*** Begin Patch" in t]
    result = [op for text in patches for op in patch_operations(text)]
    assert len(patches) <= len(PATCH_FIELDS), f"Too many patch fields: {patches}"
    return result
