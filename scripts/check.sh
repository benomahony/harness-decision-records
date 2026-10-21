#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
"${ZANITY:-zanity}" check . --rules all --fail-on warning
ruff check .
ruff format --check .
basedpyright hdr
python -m pytest -q
