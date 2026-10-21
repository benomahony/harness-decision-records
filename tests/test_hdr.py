from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

import pytest

from hdr.cli import git
from hdr.core import Invalid, decode, equal, local, resolve

PROJECT = Path(__file__).resolve().parents[1]
RUNNER = PROJECT / "hdr/runner.py"
RECORD = ".hdr/decisions/HDR-001.json"
# Drive the generated plugins under Node with stand-in harness APIs, so the real
# shim code, subprocess call and checker run end to end.
PI_DRIVER = """
const [module, cwd] = process.argv.slice(2)
const { default: extension } = await import(module)
const handlers = {}
extension({ on: (name, fn) => { handlers[name] = fn }, sendUserMessage: () => {} })
const ctx = { cwd, hasUI: false, sessionManager: { getSessionId: () => "node-pi" } }
await handlers.session_start({ reason: "startup" }, ctx)
const call = (toolName, input) => handlers.tool_call({ toolName, toolCallId: "1", input }, ctx)
const edit = await call("edit", { path: `${cwd}/RECORD`, edits: [] })
const read = await call("read", { path: "README.md" })
console.log(JSON.stringify({ denied: edit?.block === true, allowed: read === undefined }))
""".replace("RECORD", RECORD)
OPENCODE_DRIVER = """
const [module, cwd] = process.argv.slice(2)
const { HdrPlugin } = await import(module)
const hooks = await HdrPlugin({ directory: cwd, client: { tui: { showToast: async () => {} } } })
await hooks.event({ event: { type: "session.created", properties: { info: { id: "node-oc" } } } })
const call = async (tool, args) => {
  try {
    await hooks["tool.execute.before"]({ tool, sessionID: "node-oc", callID: "1" }, { args })
    return true
  } catch (error) {
    return false
  }
}
const denied = !(await call("edit", { filePath: `${cwd}/RECORD` }))
const allowed = await call("read", { filePath: "README.md" })
console.log(JSON.stringify({ denied, allowed }))
""".replace("RECORD", RECORD)


class PointerTests(unittest.TestCase):
    def test_escaped_tokens_empty_keys_and_arrays(self):
        data = {"a/b": {"~key": [0, {"": False}]}}
        self.assertIs(resolve(data, "/a~1b/~0key/1/"), False)
        self.assertEqual(resolve(data, ""), data)

    def test_malformed_and_missing_pointers_error(self):
        for pointer in ("a", "/~2", "/a/01", "/a/-", "/a/7", "/missing"):
            with self.subTest(pointer=pointer), self.assertRaises(Invalid):
                resolve({"a": [1]}, pointer)

    def test_bool_is_not_number_recursively(self):
        self.assertFalse(equal({"x": [True]}, {"x": [1]}))
        self.assertTrue(equal(1, 1.0))

    def test_duplicate_keys_and_nonfinite_numbers_rejected(self):
        for text in ('{"x":1,"x":2}', "NaN", "Infinity"):
            with self.assertRaises(ValueError):
                decode(text)


def test_path_escape_rejected(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "escape").symlink_to(tmp_path, target_is_directory=True)
    for name in ("../secret", "/tmp/secret", "escape/secret"):
        with pytest.raises(Invalid) as caught:
            local(root, name)
        assert "path" in str(caught.value).lower(), (
            f"Expected path diagnostic: {caught.value}"
        )


class IntegrationTests(unittest.TestCase):
    @pytest.fixture(autouse=True)
    def workspace(self, tmp_path: Path) -> None:
        assert tmp_path.is_dir(), f"pytest temporary directory missing: {tmp_path}"
        self.base = tmp_path
        self.tmp_path = tmp_path / "repo"
        self.tmp_path.mkdir()
        self.env = {
            **os.environ,
            "CLAUDE_CONFIG_DIR": str(tmp_path / "claude"),
            "XDG_STATE_HOME": str(tmp_path / "state"),
        }
        result = self.cli("init", code=0)
        assert "Created 2 HDRs" in result.stdout, (
            f"Demo initialisation failed: {result.stdout}"
        )

    def cli(self, *args, code=None, payload=None):
        assert args, "CLI test needs a command"
        assert self.tmp_path.is_dir(), f"Test repository missing: {self.tmp_path}"
        result = subprocess.run(
            [sys.executable, str(RUNNER), "--root", str(self.tmp_path), *args],
            env=self.env,
            input=json.dumps(payload) if payload else None,
            check=False,
            capture_output=True,
            text=True,
        )
        if code is not None:
            self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return result

    def event(self, name, **extra):
        assert name in ("SessionStart", "PreToolUse", "PostToolUse", "Stop"), (
            f"Unknown event: {name}"
        )
        assert "session_id" not in extra, (
            f"Fixture session cannot be overridden: {list(extra)}"
        )
        return {
            "hook_event_name": name,
            "session_id": "test-session",
            "cwd": str(self.tmp_path),
            **extra,
        }

    def install(self):
        result = self.cli("install", "claude", "--project", code=0)
        assert "Installed hooks" in result.stdout, (
            f"Hook installation failed: {result.stdout}"
        )
        assert (self.tmp_path / ".claude/settings.json").is_file(), (
            "Hook settings were not written"
        )

    def state_rule(self):
        assert (self.tmp_path / ".hdr/decisions").is_dir(), (
            "Initialise the repository first"
        )
        record = {
            "schema_version": 1,
            "id": "HDR-006",
            "title": "Budget is event",
            "rationale": "Event expenses belong to the event budget",
            "check": {
                "kind": "json_equals",
                "path": "expense.json",
                "pointer": "/budget",
                "expected": "event",
            },
        }
        (self.tmp_path / ".hdr/decisions/HDR-006.json").write_text(json.dumps(record))
        (self.tmp_path / "expense.json").write_text('{"budget":"event"}')
        assert len(list((self.tmp_path / ".hdr/decisions").glob("*.json"))) == 3, (
            "State fixture needs three records"
        )

    def record(self, rid, **extra):
        assert rid.startswith("HDR-"), f"Fixture record needs a decision ID: {rid}"
        assert "id" not in extra, f"Fixture ID cannot be overridden: {list(extra)}"
        return {
            "schema_version": 1,
            "id": rid,
            "title": f"Record {rid}",
            "rationale": "Fixture record",
            "check": {"kind": "path_exists", "path": ".hdr"},
            **extra,
        }

    def pre(self, tool, path, content=None):
        assert tool, "PreToolUse fixture needs a tool name"
        assert Path(path).is_absolute(), f"Fixture path must be absolute: {path}"
        tool_input = {"file_path": str(path)}
        if content is not None:
            tool_input["content"] = json.dumps(content)
        payload = self.event("PreToolUse", tool_name=tool, tool_input=tool_input)
        return json.loads(self.cli("hook", payload=payload, code=0).stdout)

    def native(self, harness, name, **extra):
        """Send one hook event as a non-Claude harness and return its response."""
        assert harness in ("codex", "opencode", "pi"), f"Unknown harness: {harness}"
        payload = self.event(name, **extra)
        out = self.cli("hook", "--harness", harness, payload=payload, code=0)
        assert out.stdout.strip(), f"{harness} hook printed nothing: {out.stderr}"
        return json.loads(out.stdout)

    def entry(self, title, **extra):
        """One live history entry with a trivially passing check."""
        assert title, "History entries need a title"
        check = extra.pop("check", {"kind": "path_exists", "path": ".hdr"})
        result = {"title": title, "rationale": f"Why {title}", "check": check, **extra}
        assert "kind" in result["check"], f"Entry check needs a kind: {result}"
        return result

    def decision(self, rid, *history):
        assert history, f"Decision {rid} needs at least one entry"
        result = {"schema_version": 2, "id": rid, "history": list(history)}
        assert result["history"][0], f"Decision {rid} starts empty"
        return result

    def write_decision(self, rid, *history):
        assert rid.startswith("HDR-"), f"Decision fixture needs an ID: {rid}"
        path = self.tmp_path / f".hdr/decisions/{rid}.json"
        path.write_text(json.dumps(self.decision(rid, *history), indent=2))
        assert path.is_file(), f"Decision fixture was not written: {path}"
        return path

    def read_allowed(self):
        """PreToolUse for a harmless read; {} means nothing failed."""
        assert self.tmp_path.is_dir(), f"Test repository missing: {self.tmp_path}"
        out = self.cli(
            "hook", payload=self.event("PreToolUse", tool_name="Read"), code=0
        )
        assert out.stdout.strip(), f"Hook printed nothing: {out.stderr}"
        return json.loads(out.stdout)

    def test_person_can_append_history_mid_session(self):
        """Appending an entry is accepted mid-session; rewriting one is not."""
        self.install()
        path = self.write_decision("HDR-006", self.entry("Budgets are per team"))
        self.cli("hook", payload=self.event("SessionStart"), code=0)
        first, second = self.entry("Budgets are per team"), self.entry("Per event")
        self.write_decision("HDR-006", first, second)
        self.assertEqual(self.read_allowed(), {})
        self.assertIn("PASS: 3 current", self.cli("validate", code=0).stdout)
        self.write_decision("HDR-006", self.entry("Rewritten"), second)
        self.assertIn(
            f"changed .hdr/decisions/{path.name}", json.dumps(self.read_allowed())
        )

    def test_retired_decision_is_not_enforced(self):
        """The latest entry decides: a retirement takes the rule out of force."""
        self.install()
        deny = self.entry("No shell", check={"kind": "tool_denied", "tools": ["Bash"]})
        retire = {"date": "2026-10-21", "status": "retired", "rationale": "Too blunt"}
        self.write_decision("HDR-006", deny, retire)
        self.assertIn(
            "PASS: 2 current decisions (3 decision files)",
            self.cli("validate", code=0).stdout,
        )
        self.cli("hook", payload=self.event("SessionStart"), code=0)
        out = self.cli(
            "hook", payload=self.event("PreToolUse", tool_name="Bash"), code=0
        )
        self.assertEqual(json.loads(out.stdout), {})
        self.write_decision("HDR-007", retire)
        self.assertIn("must start with a decision", self.cli("validate", code=2).stderr)

    def test_single_record_converts_to_history(self):
        """A schema 1 record may become the first entry of a schema 2 history."""
        self.install()
        old = self.record("HDR-006")
        (self.tmp_path / ".hdr/decisions/HDR-006.json").write_text(json.dumps(old))
        self.cli("hook", payload=self.event("SessionStart"), code=0)
        first = {k: old[k] for k in ("title", "rationale", "check")}
        self.write_decision(
            "HDR-006", {**first, "date": "2026-10-21"}, self.entry("Next")
        )
        self.assertEqual(self.read_allowed(), {})

    def hooks_record(self, rid, harnesses):
        assert harnesses, "Hook record fixture needs at least one harness"
        check = {"kind": "hdr_hooks", "harnesses": harnesses, "events": ["Stop"]}
        path = self.tmp_path / f".hdr/decisions/{rid}.json"
        path.write_text(json.dumps(self.record(rid, check=check)))
        assert path.is_file(), f"Hook record fixture was not written: {path}"
        return path

    def statuses(self):
        out = self.cli("check", "--json")
        assert out.returncode in (0, 1), f"Check could not run: {out.stderr}"
        found = {f["id"]: f for f in json.loads(out.stdout)["findings"]}
        assert found, f"Check reported no findings: {out.stdout}"
        return found

    def node(self, harness, shim, driver):
        """Run a generated plugin under Node with a stand-in harness API."""
        assert shim.is_file(), f"Plugin shim is missing: {shim}"
        module = self.base / f"{harness}-shim.mjs"
        module.write_text(shim.read_text())
        script = self.base / f"{harness}-driver.mjs"
        script.write_text(driver)
        result = subprocess.run(
            ["node", str(script), str(module), str(self.tmp_path)],
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, f"{harness} shim failed: {result.stderr}"
        return json.loads(result.stdout)

    def test_codex_hooks_install_and_apply_patch_is_guarded(self):
        """Codex uses Claude-shaped hooks.json; apply_patch file ops are checked."""
        self.install()
        out = self.cli("install", "codex", "--project", code=0)
        hooks = self.tmp_path / ".codex/hooks.json"
        self.assertIn(str(hooks), out.stdout)
        self.assertIn("--harness codex", hooks.read_text())
        self.hooks_record("HDR-006", ["codex"])
        self.assertEqual(self.statuses()["HDR-006"]["status"], "PASS")
        self.native("codex", "SessionStart")
        wrap = lambda body: {"command": f"*** Begin Patch\n{body}\n*** End Patch"}  # noqa: E731
        out = self.native(
            "codex",
            "PreToolUse",
            tool_name="apply_patch",
            tool_input=wrap(f"*** Update File: {RECORD}\n@@\n-a\n+b"),
        )
        self.assertIn(
            "would change", out["hookSpecificOutput"]["permissionDecisionReason"]
        )
        added = json.dumps(self.record("HDR-007"), indent=2).splitlines()
        body = "\n".join(
            [
                "*** Add File: .hdr/decisions/HDR-007.json",
                *("+" + line for line in added),
            ]
        )
        out = self.native(
            "codex", "PreToolUse", tool_name="apply_patch", tool_input=wrap(body)
        )
        self.assertEqual(out, {})

    def test_plugin_shims_install_and_detect_tampering(self):
        """opencode and pi plugins count as registered only while unmodified."""
        for harness in ("opencode", "pi"):
            self.cli("install", harness, "--project", code=0)
        self.hooks_record("HDR-006", ["opencode", "pi"])
        self.assertEqual(self.statuses()["HDR-006"]["status"], "PASS")
        shim = self.tmp_path / ".pi/extensions/hdr.ts"
        shim.write_text(shim.read_text() + "\n// local tweak\n")
        finding = self.statuses()["HDR-006"]
        self.assertEqual(finding["status"], "FAIL")
        self.assertIn(
            "pi Stop: HDR hook missing; run hdr install pi --project",
            finding["message"],
        )

    def test_native_file_tools_are_normalised(self):
        """Each harness's own edit and write tools hit the append-only guard."""
        self.install()
        record = str(self.tmp_path / RECORD)
        delete = f"*** Begin Patch\n*** Delete File: {RECORD}\n*** End Patch"
        for harness, tool, data in [
            ("opencode", "edit", {"filePath": record}),
            ("opencode", "write", {"filePath": record, "content": "{}"}),
            ("opencode", "apply_patch", {"patchText": delete}),
            ("pi", "edit", {"path": record, "edits": []}),
            ("pi", "write", {"path": RECORD, "content": "{}"}),
        ]:
            with self.subTest(harness=harness, tool=tool):
                self.native(harness, "SessionStart")
                out = self.native(
                    harness, "PreToolUse", tool_name=tool, tool_input=data
                )
                self.assertEqual(
                    out["hookSpecificOutput"]["permissionDecision"], "deny"
                )
        out = self.native(
            "pi", "PreToolUse", tool_name="read", tool_input={"path": record}
        )
        self.assertEqual(out, {})

    @unittest.skipUnless(shutil.which("node"), "Node is needed to run the plugin shims")
    def test_plugin_shims_block_record_edits_end_to_end(self):
        """The generated plugins call the checker and turn a deny into a block."""
        self.install()
        for harness, path, driver in [
            ("pi", ".pi/extensions/hdr.ts", PI_DRIVER),
            ("opencode", ".opencode/plugins/hdr.ts", OPENCODE_DRIVER),
        ]:
            with self.subTest(harness=harness):
                self.cli("install", harness, "--project", code=0)
                out = self.node(harness, self.tmp_path / path, driver)
                self.assertEqual(out, {"denied": True, "allowed": True})

    def test_fresh_clone_fails_then_install_passes(self):
        self.cli("validate", code=0)
        self.cli("check", code=1)
        self.install()
        result = self.cli("check", code=0)
        self.assertIn("PASS", result.stdout)

    def test_install_preserves_settings_and_is_idempotent(self):
        path = self.tmp_path / ".claude/settings.json"
        path.parent.mkdir()
        path.write_text('{"permissions":{"deny":["WebFetch"]}}')
        self.install()
        before = path.read_text()
        self.install()
        self.assertEqual(before, path.read_text())
        self.assertEqual(json.loads(before)["permissions"]["deny"], ["WebFetch"])
        self.assertTrue(path.with_name("settings.json.hdr-backup").exists())

    def test_user_install_discovers_new_repo(self):
        self.cli("install", "claude", "--user", code=0)
        self.cli("check", code=0)
        out = self.cli("hook", payload=self.event("SessionStart"), code=0)
        self.assertIn("HDR PASS", json.loads(out.stdout)["systemMessage"])

    def test_startup_alert_on_missing_configuration(self):
        out = self.cli("hook", payload=self.event("SessionStart"), code=0)
        self.assertIn("HDR FAILED", json.loads(out.stdout)["systemMessage"])

    def test_denied_tool_and_allowed_tool(self):
        self.install()
        denial = self.record(
            "HDR-006", check={"kind": "tool_denied", "tools": ["Bash"]}
        )
        (self.tmp_path / ".hdr/decisions/HDR-006.json").write_text(json.dumps(denial))
        self.cli("hook", payload=self.event("SessionStart"), code=0)
        out = self.cli(
            "hook", payload=self.event("PreToolUse", tool_name="Bash"), code=0
        )
        self.assertEqual(
            json.loads(out.stdout)["hookSpecificOutput"]["permissionDecision"], "deny"
        )
        out = self.cli(
            "hook", payload=self.event("PreToolUse", tool_name="Read"), code=0
        )
        self.assertEqual(json.loads(out.stdout), {})

    def test_missing_session_baseline_denies(self):
        self.install()
        out = self.cli(
            "hook", payload=self.event("PreToolUse", tool_name="Read"), code=0
        )
        self.assertIn("No SessionStart baseline", out.stdout)

    def test_post_edit_violation_and_repair_remain_possible(self):
        self.install()
        self.state_rule()
        self.cli("hook", payload=self.event("SessionStart"), code=0)
        (self.tmp_path / "expense.json").write_text('{"budget":"discretionary"}')
        out = self.cli(
            "hook", payload=self.event("PostToolUse", tool_name="Edit"), code=0
        )
        self.assertEqual(json.loads(out.stdout)["decision"], "block")
        out = self.cli(
            "hook", payload=self.event("PreToolUse", tool_name="Edit"), code=0
        )
        self.assertEqual(json.loads(out.stdout), {})
        self.cli("check", code=1)
        (self.tmp_path / "expense.json").write_text('{"budget":"event"}')
        self.cli("check", code=0)

    def test_mid_session_policy_change_denied(self):
        self.install()
        self.cli("hook", payload=self.event("SessionStart"), code=0)
        (self.tmp_path / ".hdr/decisions/HDR-001.json").unlink()
        out = self.cli(
            "hook", payload=self.event("PreToolUse", tool_name="Read"), code=0
        )
        self.assertIn("removed .hdr/decisions/HDR-001.json", out.stdout)
        self.assertIn('"deny"', out.stdout)

    def test_existing_records_cannot_be_edited_or_replaced(self):
        self.install()
        self.cli("hook", payload=self.event("SessionStart"), code=0)
        target = self.tmp_path / ".hdr/decisions/HDR-001.json"
        for tool in ("Edit", "MultiEdit"):
            out = self.pre(tool, target)
            self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        out = self.pre("Write", target, self.record("HDR-001"))
        self.assertIn(
            "would change", out["hookSpecificOutput"]["permissionDecisionReason"]
        )
        self.assertEqual(self.pre("Write", self.tmp_path / "notes.md"), {})

    def test_records_can_be_appended_mid_session(self):
        """Valid new records are allowed mid-session and pinned once written."""
        self.install()
        self.cli("hook", payload=self.event("SessionStart"), code=0)
        path = self.tmp_path / ".hdr/decisions/HDR-006.json"
        self.assertEqual(self.pre("Write", path, self.record("HDR-006")), {})
        for content, reason in [
            ({"id": "HDR-006"}, "invalid"),
            (self.record("HDR-001"), "already exists"),
            (self.record("HDR-006", supersedes=["HDR-002"]), "ask the user"),
            (self.decision("HDR-006", self.entry("A"), self.entry("B")), "one entry"),
        ]:
            out = self.pre("Write", path, content)
            self.assertIn(reason, out["hookSpecificOutput"]["permissionDecisionReason"])
        path.write_text(json.dumps(self.record("HDR-006")))
        out = self.cli(
            "hook", payload=self.event("PostToolUse", tool_name="Write"), code=0
        )
        self.assertEqual(json.loads(out.stdout), {})
        path.write_text(json.dumps(self.record("HDR-006", title="Changed")))
        out = self.cli(
            "hook", payload=self.event("PreToolUse", tool_name="Read"), code=0
        )
        self.assertIn("changed .hdr/decisions/HDR-006.json", out.stdout)

    def test_resume_keeps_session_baseline(self):
        self.install()
        self.cli("hook", payload=self.event("SessionStart"), code=0)
        target = self.tmp_path / ".hdr/decisions/HDR-002.json"
        target.write_text(target.read_text().replace("Register", "Skip"))
        out = self.cli("hook", payload=self.event("SessionStart"), code=0)
        message = json.loads(out.stdout)["systemMessage"]
        self.assertIn("changed .hdr/decisions/HDR-002.json", message)

    def test_superseded_rule_is_inactive(self):
        self.install()
        decisions = self.tmp_path / ".hdr/decisions"
        denial = self.record(
            "HDR-006", check={"kind": "tool_denied", "tools": ["Bash"]}
        )
        (decisions / "HDR-006.json").write_text(json.dumps(denial))
        retire = self.record("HDR-007", supersedes=["HDR-006"])
        (decisions / "HDR-007.json").write_text(json.dumps(retire))
        self.assertIn("PASS: 3", self.cli("validate", code=0).stdout)
        self.cli("hook", payload=self.event("SessionStart"), code=0)
        out = self.cli(
            "hook", payload=self.event("PreToolUse", tool_name="Bash"), code=0
        )
        self.assertEqual(json.loads(out.stdout), {})
        (decisions / "HDR-008.json").write_text(
            json.dumps(self.record("HDR-008", supersedes=["HDR-999"]))
        )
        self.cli("validate", code=2)

    def test_explain_writes_report(self):
        self.install()
        self.cli("hook", payload=self.event("SessionStart"), code=0)
        out = self.cli("explain", "--no-open", code=0)
        self.assertIn("report.html", out.stdout)
        html = (self.tmp_path / ".hdr/runs/report.html").read_text()
        self.assertIn("Decision records are append-only", html)
        self.assertIn("SessionStart", html)

    def test_deleted_policy_errors_in_existing_session(self):
        self.install()
        self.cli("hook", payload=self.event("SessionStart"), code=0)
        for tmp_path in (self.tmp_path / ".hdr/decisions").glob("*.json"):
            tmp_path.unlink()
        result = self.cli(
            "hook", payload=self.event("PreToolUse", tool_name="Read"), code=2
        )
        self.assertIn("No HDR records", result.stderr)

    def test_local_bypass_and_disabled_hooks_fail(self):
        self.install()
        (self.tmp_path / ".claude/settings.local.json").write_text(
            '{"disableAllHooks":true,"permissions":{"defaultMode":"bypassPermissions"}}'
        )
        out = self.cli("check", "--json", code=1)
        ids = {f["id"] for f in json.loads(out.stdout)["findings"]}
        self.assertLessEqual({"CONFIG-HOOKS", "CONFIG-BYPASS"}, ids)

    def test_legacy_single_event_hook_records_still_parse(self):
        """Append-only records written in the old one-event shape keep working."""
        self.install()
        legacy = self.record("HDR-006", check={"kind": "claude_hook", "event": "Stop"})
        (self.tmp_path / ".hdr/decisions/HDR-006.json").write_text(json.dumps(legacy))
        out = self.cli("check", code=0)
        self.assertIn("Stop: HDR hook registered on disk", out.stdout)

    def test_partial_hook_registration_names_missing_events(self):
        """One multi-event record fails naming only the unregistered events."""
        self.install()
        path = self.tmp_path / ".claude" / "settings.json"
        settings = json.loads(path.read_text())
        del settings["hooks"]["Stop"]
        path.write_text(json.dumps(settings))
        out = self.cli("check", code=1)
        self.assertIn("Stop: HDR hook missing", out.stdout)

    def test_session_start_explains_decision_grain(self):
        """Agents are told what one decision record should cover."""
        out = self.cli("hook", payload=self.event("SessionStart"), code=0)
        context = json.loads(out.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertIn("one decision per record", context)

    def test_malformed_rules_fail_closed(self):
        path = self.tmp_path / ".hdr/decisions/HDR-002.json"
        path.write_text('{"schema_version":1,"check":{"kind":"llm_judge"}}')
        self.cli("validate", code=2)
        result = self.cli("check", code=2)
        self.assertIn("HDR ERROR", result.stderr)

    def test_missing_state_file_errors(self):
        self.install()
        self.state_rule()
        (self.tmp_path / "expense.json").unlink()
        result = self.cli("check", code=2)
        self.assertIn("ERROR", result.stdout)

    def test_stop_does_not_loop(self):
        self.install()
        self.state_rule()
        (self.tmp_path / "expense.json").write_text('{"budget":"wrong"}')
        out = self.cli("hook", payload=self.event("Stop"), code=0)
        self.assertEqual(json.loads(out.stdout)["decision"], "block")
        out = self.cli(
            "hook", payload=self.event("Stop", stop_hook_active=True), code=0
        )
        self.assertNotIn("decision", json.loads(out.stdout))
        self.assertIn("systemMessage", json.loads(out.stdout))

    def test_git_trace_and_no_tool_inputs_saved(self):
        """Trace the recorded Git revision without storing sensitive tool inputs."""
        self.install()
        self.state_rule()
        for args in [
            ("init", "-q"),
            ("add", "."),
            (
                "-c",
                "user.name=HDR Test",
                "-c",
                "user.email=hdr@example.invalid",
                "commit",
                "-qm",
                "Set event budget rule",
            ),
        ]:
            result = git(self.tmp_path, list(args))
            self.assertIsNotNone(result)
        self.cli("hook", payload=self.event("SessionStart"), code=0)
        self.cli(
            "hook",
            payload=self.event(
                "PreToolUse",
                tool_name="Read",
                tool_input={"secret": "must-not-be-recorded"},
            ),
            code=0,
        )
        out = self.cli("check", "--json", code=0)
        run_id = json.loads(out.stdout)["run_id"]
        out = self.cli("trace", run_id, "--decision", "HDR-006", code=0)
        self.assertIn("Set event budget rule", out.stdout)
        for tmp_path in (self.tmp_path / ".hdr/runs").glob("*.json"):
            self.assertNotIn("must-not-be-recorded", tmp_path.read_text())

    def test_trace_cannot_escape_run_directory(self):
        result = self.cli("trace", "../../anything", code=2)
        self.assertIn("run ID", result.stderr)
