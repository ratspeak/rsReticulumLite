#!/usr/bin/env bash
# Live Python golden-master gate for the resource layer: build+run the rns-lite-core emitter test
# (real lite-emitted advertisement/parts/requests/proof) and pipe its output through an unmodified
# Python RNS Resource (accept -> request -> reassemble -> prove -> validate). Hard-requires the
# exact version recorded in vectors/RNS_VERSION — no skip, no pip install. Run from anywhere.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(dirname "$here")"
target_rns="$(tr -d '[:space:]' < "$here/RNS_VERSION")"

TARGET_RNS="$target_rns" python3 - <<'EOF'
import os
import sys
target = os.environ["TARGET_RNS"]
try:
    import RNS
except ImportError:
    print(f"ERROR: Python RNS is not installed (pinned parity target: {target})", file=sys.stderr)
    sys.exit(1)
if RNS.__version__ != target:
    print(f"ERROR: pinned parity target is RNS {target}, found {RNS.__version__}", file=sys.stderr)
    sys.exit(1)
EOF

out="$(cargo test --manifest-path "$repo/Cargo.toml" -p rns-lite-core --test resource_vectors \
    emit_resource_transfer_for_python -- --exact --nocapture)"
echo "$out" | grep -c "^test .* ok$" >/dev/null
echo "$out" | python3 "$here/verify_rust_resource.py"
echo "vectors/run.sh: PASS"
