#!/bin/bash
# tests/run.sh - run the SentinelForge Lab e2e suite (zero npm dependencies).
#
# Usage:
#   ./tests/run.sh                    # run everything against http://localhost:3001
#   ./tests/run.sh tests/e2e/auth.test.mjs
#   SENTINELFORGE_API_URL=http://localhost/api ./tests/run.sh
#
# Node's test runner treats a bare directory argument as a module path on some
# builds, so the suite is invoked with an explicit *.test.mjs glob instead.
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
API="${SENTINELFORGE_API_URL:-http://localhost:3001}"

if [ -f "$ROOT/scripts/lib.sh" ]; then
  API="$API" . "$ROOT/scripts/lib.sh"
  wait_for_api 60 || exit 1
fi

if [ "$#" -gt 0 ]; then
  TARGETS=("$@")
else
  TARGETS=("$DIR/e2e/"*.test.mjs)
fi

echo "Running SentinelForge Lab e2e tests against ${API} ..."
node --test "${TARGETS[@]}"