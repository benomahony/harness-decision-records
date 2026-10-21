from __future__ import annotations

import os
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path

from hdr.core import EVENTS, HARNESSES, JSON, Finding, Invalid, digest, obj, read


def command_args(harness: str = "claude") -> list[str]:
    """Argument vector a harness runs; Claude keeps the original bare form."""
    assert harness in HARNESSES, f"Unsupported harness: {harness}"
    runner = Path(__file__).with_name("runner.py").resolve()
    assert runner.is_file(), f"Hook entry point missing: {runner}; reinstall HDR"
    assert Path(sys.executable).is_file(), (
        f"Python interpreter missing: {sys.executable}"
    )
    extra = [] if harness == "claude" else ["--harness", harness]
    return [sys.executable, str(runner), "hook", *extra]


def command(harness: str = "claude") -> str:
    assert harness in HARNESSES, f"Unsupported harness: {harness}"
    result = shlex.join(command_args(harness))
    assert result.endswith("hook") or harness in result, f"Bad command: {result}"
    return result


def config_dir() -> Path:
    configured = os.environ.get("CLAUDE_CONFIG_DIR", str(Path.home() / ".claude"))
    assert configured, "CLAUDE_CONFIG_DIR is empty; unset it or provide a directory"
    target = Path(configured).expanduser()
    assert target.is_absolute(), f"CLAUDE_CONFIG_DIR must be absolute: {target}"
    return target.resolve()


@dataclass(frozen=True)
class Layer:
    path: Path
    data: dict[str, JSON]
    sha256: str | None


def inspect(root: Path) -> tuple[list[Layer], list[Finding]]:
    assert root.is_absolute(), f"Repository root must be absolute: {root}"
    assert root.is_dir(), f"Repository directory is missing: {root}"
    paths = [
        config_dir() / "settings.json",
        root / ".claude/settings.json",
        root / ".claude/settings.local.json",
    ]
    layers: list[Layer] = []
    findings: list[Finding] = []
    for path in dict.fromkeys(paths):
        source = str(path)
        try:
            data = obj(read(path)) if path.exists() else {}
            layers.append(Layer(path, data, digest(path) if path.exists() else None))
            # Conservative conflict detection, NOT a full reproduction of Claude precedence.
            if data.get("disableAllHooks") is True:
                findings.append(
                    Finding("CONFIG-HOOKS", "FAIL", "disableAllHooks is true", source)
                )
            perms = obj(data.get("permissions", {}))
            if perms.get("defaultMode") == "bypassPermissions":
                findings.append(
                    Finding(
                        "CONFIG-BYPASS", "FAIL", "bypassPermissions configured", source
                    )
                )
            if data.get("allowManagedHooksOnly") is True:
                findings.append(
                    Finding(
                        "CONFIG-MANAGED",
                        "ERROR",
                        "Managed-only hooks are outside this adapter profile",
                        source,
                    )
                )
        except (OSError, ValueError, AssertionError, RecursionError) as exc:
            findings.append(
                Finding(
                    "CONFIG-READ", "ERROR", f"Cannot inspect settings: {exc}", source
                )
            )
    return layers, findings


def registered(layers: list[Layer], event: str, harness: str = "claude") -> list[str]:
    """Layers that run the HDR command synchronously for every match of event."""
    assert event in EVENTS, f"Unsupported hook event: {event}"
    assert len(layers) <= 3, (
        f"Adapter accepts only user, project and local layers (observed={len(layers)})"
    )
    sources: list[str] = []
    for layer in layers:
        hooks = obj(layer.data.get("hooks", {}))
        groups = hooks.get(event, [])
        if not isinstance(groups, list):
            raise Invalid(f"{layer.path}: hooks.{event} must be an array")
        for value in groups:
            group = obj(value)
            if group.get("matcher", "") not in ("", "*"):
                continue
            entries = group.get("hooks", [])
            if not isinstance(entries, list):
                raise Invalid("hooks must be an array")
            for entry in entries:
                hook = obj(entry)
                if (
                    hook.get("type") == "command"
                    and hook.get("command") == command(harness)
                    and hook.get("async", False) is False
                ):
                    sources.append(str(layer.path))
    return sources
