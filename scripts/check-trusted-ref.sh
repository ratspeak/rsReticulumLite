#!/usr/bin/env sh
# Trusted-drift tripwire: warn by default when a trusted sibling repo has moved
# past the commit this repo was last audited against. Flow: run the full matrix
# against the new trusted HEAD, port/adapt any behavior change INTO this crate,
# then update TRUSTED_REF to the new hash. Pass --strict in CI/release gates.
set -eu
cd "$(dirname "$0")/.."

strict=0
case "${1:-}" in
  "") ;;
  --strict) strict=1 ;;
  *) echo "usage: $0 [--strict]" >&2; exit 2 ;;
esac

drift=0
while read -r name ref; do
  case "$name" in ""|\#*) continue ;; esac
  head="$(git -C "../$name" rev-parse HEAD 2>/dev/null || echo MISSING)"
  if [ "$head" != "$ref" ]; then
    echo "!! TRUSTED DRIFT: ../$name is at $head" >&2
    echo "!!   last audited against $ref (TRUSTED_REF)" >&2
    echo "!!   run the matrix, port any behavior change, then bump TRUSTED_REF" >&2
    drift=1
  fi
done < TRUSTED_REF
[ "$drift" -eq 0 ] && echo "trusted refs current (TRUSTED_REF)"
[ "$strict" -eq 1 ] && [ "$drift" -ne 0 ] && exit 1
exit 0
