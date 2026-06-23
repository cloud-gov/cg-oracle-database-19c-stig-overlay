#!/usr/bin/env bash
#
# One-command verify for the 12c -> 19c control migration tool.
#
# Runs the migrate_controls.py unit tests. Intended to be the single
# verification entry point referenced by AGENTS.md (one-command verify).
#
# Usage:
#   ./12c_to_19c/verify.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Running migrate_controls unit tests"
python3 -m unittest discover -s "${SCRIPT_DIR}" -p 'test_*.py' -v

echo "==> All checks passed"
