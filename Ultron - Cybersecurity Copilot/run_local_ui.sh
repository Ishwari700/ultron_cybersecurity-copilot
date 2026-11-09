#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

if [ -f ".venv/bin/python" ]; then
    PYTHON_EXE=".venv/bin/python"
elif command -v python3 &>/dev/null; then
    PYTHON_EXE="python3"
else
    PYTHON_EXE="python"
fi

"$PYTHON_EXE" run_local_ui.py
