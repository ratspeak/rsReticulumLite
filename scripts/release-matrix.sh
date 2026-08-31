#!/usr/bin/env sh
set -eu

ROOT="$(dirname "$0")/.."

cd "$ROOT"
./scripts/check-trusted-ref.sh --strict
./scripts/test-matrix.sh
# Release adds the hard-pinned live-Python golden master (see vectors/RNS_VERSION).
./vectors/run.sh
