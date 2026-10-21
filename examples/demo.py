"""Run a complete isolated demonstration without installing user hooks."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def create_expense_history(repo: Path) -> Path:
    assert repo.is_dir(), f"Demo repository missing: {repo}"
    assert (repo / ".hdr/decisions").is_dir(), f"Demo decisions missing: {repo}"
    record = {
        "schema_version": 1,
        "id": "HDR-006",
        "title": "Expense belongs to the event budget",
        "rationale": "Event travel must be charged to the event.",
        "check": {
            "kind": "json_equals",
            "path": "expense.json",
            "pointer": "/budget",
            "expected": "event",
        },
    }
    (repo / ".hdr/decisions/HDR-006.json").write_text(json.dumps(record, indent=2))
    expense = repo / "expense.json"
    expense.write_text('{"budget":"event"}\n')
    for args in (
        ["init", "-q"],
        ["add", "."],
        [
            "-c",
            "user.name=HDR Demo",
            "-c",
            "user.email=hdr@example.invalid",
            "commit",
            "-qm",
            "Require event allocation",
        ],
    ):
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)
    return expense


def forbidden_edit(event: dict[str, object], repo: Path) -> dict[str, object]:
    """A PreToolUse payload in which the agent edits an existing decision record."""
    record = repo / ".hdr/decisions/HDR-001.json"
    assert record.is_file(), f"Seeded record is missing: {record}"
    assert event.get("session_id"), f"Demo event needs a session: {event}"
    payload = {**event, "hook_event_name": "PreToolUse", "tool_name": "Edit"}
    return {**payload, "tool_input": {"file_path": str(record)}}


def main() -> None:
    base = Path(tempfile.mkdtemp(prefix="hdr-demo-"))
    repo = base / "repo"
    repo.mkdir()
    assert repo.is_dir(), f"Demo directory was not created: {repo}"
    runner = Path(__file__).resolve().parents[1] / "hdr/runner.py"
    assert runner.is_file(), (
        f"HDR runner is missing: {runner}; extract the complete project"
    )
    env = {
        **os.environ,
        "CLAUDE_CONFIG_DIR": str(base / "claude"),
        "XDG_STATE_HOME": str(base / "state"),
    }

    def run(
        arguments: list[str],
        expected: int = 0,
        payload: dict[str, object] | None = None,
    ) -> str:
        assert arguments, "Demo subprocess needs a command"
        assert expected in (0, 1, 2), f"Invalid expected HDR exit status: {expected}"
        result = subprocess.run(
            [sys.executable, str(runner), "--root", str(repo), *arguments],
            env=env,
            check=False,
            capture_output=True,
            text=True,
            input=json.dumps(payload) if payload else None,
        )
        if result.returncode != expected:
            raise RuntimeError(result.stdout + result.stderr)
        print(result.stdout.strip())
        return result.stdout

    print(f"Demo repository: {repo}")
    run(["init"])
    print("\n1. Fresh clone: missing configuration")
    run(["check"], 1)
    print("\n2. Install project hooks and check again")
    run(["install", "claude", "--project"])
    expense = create_expense_history(repo)
    run(["check"])
    print("\n3. Simulated Claude startup and a forbidden edit to an existing record")
    event: dict[str, object] = {
        "session_id": "demo",
        "cwd": str(repo),
        "hook_event_name": "SessionStart",
    }
    run(["hook"], payload=event)
    run(["hook"], payload=forbidden_edit(event, repo))
    print("\n4. Introduce an allocation violation, then trace the failed record")
    expense.write_text('{"budget":"discretionary"}\n')
    result = json.loads(run(["check", "--json"], 1))
    run(["trace", result["run_id"], "--decision", "HDR-006"])
    print("\n5. Repair the allocation")
    expense.write_text('{"budget":"event"}\n')
    run(["check"])
    print(f"Complete. Inspect the saved reports in {repo}/.hdr/runs/")


if __name__ == "__main__":
    main()
