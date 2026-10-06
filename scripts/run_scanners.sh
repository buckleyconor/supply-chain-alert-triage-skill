#!/usr/bin/env bash
# Corroborate deterministic findings with established SCA scanners.
# Report-only: runs osv-scanner (if installed) and `npm audit` and captures output.
# Never modifies dependencies. Exit code is always 0 so the caller can parse results.
#
# Usage:
#   run_scanners.sh OUTDIR ROOT [ROOT ...]
#
#   OUTDIR  directory to write scanner output files into
#   ROOT    one or more project roots to scan
set -u

OUTDIR="${1:?usage: run_scanners.sh OUTDIR ROOT [ROOT ...]}"
shift
mkdir -p "$OUTDIR"
ROOTS=("$@")

echo "== Supply-chain scanner corroboration =="
echo "roots: ${ROOTS[*]}"
echo

# ---- osv-scanner (covers npm, PyPI, Cargo lockfiles from one tool) ----
if command -v osv-scanner >/dev/null 2>&1; then
  echo "[osv-scanner] found: $(osv-scanner --version 2>&1 | head -1)"
  for r in "${ROOTS[@]}"; do
    [ -d "$r" ] || continue
    safe=$(echo "$r" | tr '/ ' '__')
    osv-scanner scan --recursive --format json "$r" \
      > "$OUTDIR/osv_${safe}.json" 2> "$OUTDIR/osv_${safe}.err"
    echo "  scanned $r -> $OUTDIR/osv_${safe}.json"
  done
else
  echo "[osv-scanner] NOT installed. Install: https://github.com/google/osv-scanner (go install, brew, or apt)"
fi
echo

# ---- npm audit (per npm project that has a lockfile) ----
if command -v npm >/dev/null 2>&1; then
  echo "[npm audit] npm found: $(npm --version 2>&1)"
  i=0
  for r in "${ROOTS[@]}"; do
    [ -d "$r" ] || continue
    while IFS= read -r lock; do
      proj=$(dirname "$lock")
      case "$proj" in *node_modules*) continue;; esac
      i=$((i+1))
      ( cd "$proj" && npm audit --json ) \
        > "$OUTDIR/npmaudit_${i}.json" 2> "$OUTDIR/npmaudit_${i}.err"
      echo "  audited $proj -> $OUTDIR/npmaudit_${i}.json"
    done < <(find "$r" -name package-lock.json -not -path '*/node_modules/*' 2>/dev/null)
  done
  [ "$i" -eq 0 ] && echo "  no package-lock.json files found to audit"
else
  echo "[npm audit] npm NOT installed."
fi
echo
echo "Done. Raw scanner output in: $OUTDIR"
exit 0