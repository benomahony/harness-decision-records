"""Human-readable HTML view of the decision log, its evaluation and recent hook runs."""

from __future__ import annotations

import json
from html import escape
from pathlib import Path

from hdr.claude import Layer
from hdr.core import EVENTS, HARNESSES, JSON, Finding, Rule, records
from hdr.harnesses import sources

STYLE = """
:root{--bg:#f7f7f5;--card:#fff;--ink:#1c1c1a;--muted:#6b6b66;--line:#e4e3de;
--pass:#1f7a4d;--pass-bg:#e3f3ea;--fail:#b42318;--fail-bg:#fdecea;--warn:#8a5a00;
--warn-bg:#fdf3dc;--info:#3b5bab;--info-bg:#e8eefb;--off:#6b6b66;--off-bg:#eeeeea}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--card:#1e1e1c;--ink:#ecebe6;
--muted:#a3a29b;--line:#33332f;--pass:#6fd3a0;--pass-bg:#173326;--fail:#ff8a7a;
--fail-bg:#3a1a16;--warn:#f0c060;--warn-bg:#3a2d10;--info:#9db4ff;--info-bg:#1d2540;
--off:#a3a29b;--off-bg:#2a2a27}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,sans-serif}
main{max-width:960px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:26px;margin:0 0 4px}
h2{font-size:17px;margin:40px 0 12px}
code,.id{font:13px ui-monospace,SFMono-Regular,Menlo,monospace}
.id{font-weight:600}
.muted{color:var(--muted)}
.summary{display:flex;gap:12px;flex-wrap:wrap;margin-top:20px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;min-width:130px}
.stat b{display:block;font-size:22px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:12px}
.card.superseded{opacity:.6}
.head{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.chip{font-size:12px;font-weight:600;padding:2px 8px;border-radius:999px;white-space:nowrap}
.pass{color:var(--pass);background:var(--pass-bg)}
.fail{color:var(--fail);background:var(--fail-bg)}
.error{color:var(--warn);background:var(--warn-bg)}
.hooks{color:var(--info);background:var(--info-bg)}
.off{color:var(--off);background:var(--off-bg)}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 12px;margin:12px 0 0}
dt{color:var(--muted)}
dd{margin:0;overflow-wrap:anywhere}
.scroll{overflow-x:auto;border:1px solid var(--line);border-radius:10px}
table{width:100%;border-collapse:collapse;background:var(--card)}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:0}
th{font-size:12px;color:var(--muted);font-weight:600}
footer{margin-top:40px;font-size:13px;color:var(--muted)}
"""


CHIPS = {
    "PASS": "pass",
    "FAIL": "fail",
    "ERROR": "error",
    "HOOK-TIME": "hooks",
    "SUPERSEDED": "off",
    "RETIRED": "off",
    "NOT RUN": "off",
}


def chip(status: str) -> str:
    assert status in CHIPS, f"Unknown report status: {status}"
    assert escape(status) == status, f"Status must not need escaping: {status}"
    return f'<span class="chip {CHIPS[status]}">{escape(status)}</span>'


def worst(findings: list[Finding]) -> dict[str, str]:
    assert len(findings) <= 4096, (
        f"Finding count exceeds the display budget (observed={len(findings)})"
    )
    order = {"PASS": 0, "ERROR": 1, "FAIL": 2}
    result: dict[str, str] = {}
    for f in findings:
        if order[f.status] >= order[result.get(f.id, "PASS")]:
            result[f.id] = f.status
    assert set(result.values()) <= set(order), f"Unknown status in {result}"
    return result


def status(rule: Rule, statuses: dict[str, str], retired: dict[str, str]) -> str:
    assert rule.id, "Report status needs a decision identifier"
    assert retired.get(rule.id) != rule.id, f"{rule.id} cannot supersede itself"
    if rule.id in retired:
        return "SUPERSEDED"
    if rule.retired:
        return "RETIRED"
    if rule.id in statuses:
        return statuses[rule.id]
    return "HOOK-TIME" if rule.kind in ("append_only", "tool_denied") else "NOT RUN"


def card(rule: Rule, state: str, retired_by: str | None) -> str:
    assert state in CHIPS, f"Unknown report status for {rule.id}: {state}"
    assert retired_by != rule.id, f"{rule.id} cannot supersede itself"
    rows = [("source", rule.source)]
    rows += [(k, json.dumps(v)) for k, v in rule.check.items()]
    if rule.supersedes:
        rows.append(("supersedes", ", ".join(rule.supersedes)))
    if retired_by:
        rows.append(("superseded by", retired_by))
    details = "".join(
        f"<dt>{escape(k)}</dt><dd><code>{escape(v)}</code></dd>" for k, v in rows
    )
    faded = "superseded" if retired_by or rule.retired else ""
    return (
        f'<article class="card {faded}" id="{escape(rule.id)}">'
        f'<div class="head"><span class="id">{escape(rule.id)}</span>'
        f"<strong>{escape(rule.title)}</strong>{chip(state)}</div>"
        f'<p class="muted">{escape(rule.rationale)}</p><dl>{details}</dl>'
        f"{timeline(rule)}</article>"
    )


def timeline(rule: Rule) -> str:
    """The decision's own history, oldest first, when it has more than one entry."""
    assert rule.history or rule.source, f"{rule.id} has no history to show"
    if len(rule.history) < 2:
        return ""
    items = "".join(
        f"<li><code>{escape(str(e.get('date', '')))}</code> "
        f"{escape(str(e.get('title', 'Retired')))}"
        f'<span class="muted"> — {escape(str(e.get("rationale", "")))}</span></li>'
        for e in rule.history
    )
    html = f"<details><summary>History ({len(rule.history)} entries)</summary><ol>{items}</ol></details>"
    assert html.count("<li>") == len(rule.history), f"Timeline lost entries: {rule.id}"
    return html


def coverage(root: Path, layers: list[Layer]) -> str:
    """One row per harness, one column per event, with where HDR is registered."""
    assert root.is_absolute(), f"Coverage root must be absolute: {root}"
    head = "".join(f"<th>{event}</th>" for event in EVENTS)
    rows: list[str] = []
    for harness in HARNESSES:
        try:
            found = {event: sources(root, harness, event, layers) for event in EVENTS}
            cells = "".join(
                f"<td>{chip('PASS') if found[e] else '—'}</td>" for e in EVENTS
            )
            where = sorted({p for paths in found.values() for p in paths})
            detail = "<br>".join(f"<code>{escape(p)}</code>" for p in where) or "—"
        except ValueError as exc:
            cells = f'<td colspan="{len(EVENTS)}">{chip("ERROR")}</td>'
            detail = escape(str(exc))
        rows.append(f"<tr><td>{harness}</td>{cells}<td>{detail}</td></tr>")
    assert len(rows) == len(HARNESSES), f"Missing coverage rows: {len(rows)}"
    return (
        f'<div class="scroll"><table><tr><th>Harness</th>{head}<th>Registered in</th></tr>'
        f"{''.join(rows)}</table></div>"
    )


def run_row(run: dict[str, JSON]) -> str:
    assert "run_id" in run, "Saved run is missing its identifier"
    event = run.get("event")
    event = event if isinstance(event, dict) else {}
    found = run.get("findings")
    found = found if isinstance(found, list) else []
    failing = [
        str(f.get("id"))
        for f in found
        if isinstance(f, dict) and f.get("status") != "PASS"
    ]
    result = "PASS" if run.get("passed") is True else "FAIL"
    assert len(failing) <= len(found), f"More failures than findings: {failing}"
    return (
        f"<tr><td><code>{escape(str(run.get('timestamp', ''))[:19])}</code></td>"
        f"<td>{escape(str(event.get('hook_event_name', 'cli')))}</td>"
        f"<td>{escape(str(event.get('tool_name', '')))}</td><td>{chip(result)}</td>"
        f"<td><code>{escape(', '.join(failing))}</code></td></tr>"
    )


def runs_table(runs: list[dict[str, JSON]]) -> str:
    assert len(runs) <= 1024, f"Too many runs to display (observed={len(runs)})"
    assert all("run_id" in r for r in runs), (
        f"Every saved run needs a run_id (observed keys={[sorted(r)[:3] for r in runs]})"
    )
    if not runs:
        return '<p class="muted">No saved runs yet.</p>'
    return (
        '<div class="scroll"><table><tr><th>Time (UTC)</th><th>Event</th><th>Tool</th>'
        f"<th>Result</th><th>Not passing</th></tr>{''.join(run_row(r) for r in runs)}</table></div>"
    )


def diagnostics(findings: list[Finding], rules: list[Rule]) -> str:
    assert all(f.id for f in findings), (
        f"Every finding needs an identifier (observed={[f.id for f in findings]})"
    )
    assert all(r.id for r in rules), (
        f"Every decision needs an identifier (observed={[r.id for r in rules]})"
    )
    ids = {r.id for r in rules}
    rows = "".join(
        f"<tr><td class='id'>{escape(f.id)}</td><td>{chip(f.status)}</td>"
        f"<td>{escape(f.message)}</td><td><code>{escape(f.source)}</code></td></tr>"
        for f in findings
        if f.id not in ids
    )
    if not rows:
        return ""
    return f"<h2>Configuration findings</h2><div class='scroll'><table>{rows}</table></div>"


def render(
    data: dict[str, JSON],
    findings: list[Finding],
    layers: list[Layer],
    runs: list[dict[str, JSON]],
) -> str:
    assert data.get("run_id"), "Report rendering needs a checked result"
    assert layers, "Report rendering needs the inspected settings layers"
    root = Path(str(data["root"]))
    rules = records(root)
    statuses = worst(findings)
    retired = {s: r.id for r in rules for s in r.supersedes}
    cards = "".join(
        card(r, status(r, statuses, retired), retired.get(r.id)) for r in rules
    )
    failing = sum(1 for s in statuses.values() if s != "PASS")
    overall = "PASS" if data.get("passed") is True else "FAIL"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HDR Report</title><style>{STYLE}</style></head>
<body><main>
<h1>Harness Decision Records {chip(overall)}</h1>
<div class="muted"><code>{escape(str(data.get("root")))}</code> · generated {escape(str(data.get("timestamp"))[:19])} UTC</div>
<div class="summary">
<div class="stat"><b>{sum(1 for r in rules if r.id not in retired and not r.retired)}</b>current decisions</div>
<div class="stat"><b>{sum(1 for r in rules if r.id in retired or r.retired)}</b>retired or superseded</div>
<div class="stat"><b>{failing}</b>not passing</div>
<div class="stat"><b>{len(runs)}</b>recent runs</div>
</div>
<h2>Decision log</h2>
<p class="muted">Each decision keeps its own append-only history; the latest entry is what HDR enforces. HOOK-TIME rules are evaluated against live tool calls, not in this report.</p>
{cards}
<h2>Hook coverage</h2>
{coverage(root, layers)}
{diagnostics(findings, rules)}
<h2>Recent runs</h2>
{runs_table(runs)}
<footer><p>{escape(str(data.get("scope")))}</p>
<p>Policy <code>{escape(str(data.get("policy_sha256")))}</code> · Git HEAD <code>{escape(str(data.get("git_head")))}</code></p></footer>
</main></body></html>
"""
