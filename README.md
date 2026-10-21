# Harness Decision Records

An append-only log of the decisions that govern coding agents in a repository, checked deterministically on every hook in Claude Code, Codex, opencode and pi. Python 3.11+, no runtime dependencies, no model calls, no arbitrary checker scripts, no network requests.

## Quick start

```sh
uv tool install .
hdr init --harness claude
hdr install claude --project
hdr check
hdr explain
```

Or use `python3 -m hdr` from this directory without installing anything.

To see the whole flow in an isolated temporary repository, without touching your real harness configuration:

```sh
python3 examples/demo.py
```

## Documentation

The full documentation is a [Zine](https://zine-ssg.io) site in `docs/`:

```sh
cd docs
zine            # live preview at http://localhost:1990
zine release    # static build in docs/public/
```

It covers getting started, writing decisions and their grain, the append-only log, each harness and its gaps, the CLI, and HDR's limits.

## Verification

```sh
uv sync --group dev
uv run scripts/check.sh
```

The gate runs every deterministic Zanity rule with warnings treated as failures, Ruff, formatting, strict type checking of `hdr/`, and pytest. Tests use real files, real Git history, CLI exit codes, hook payloads for every harness, and the generated opencode and pi plugins under Node when it is installed. Runtime contracts require normal Python execution; `-O` and `PYTHONOPTIMIZE` are rejected.
