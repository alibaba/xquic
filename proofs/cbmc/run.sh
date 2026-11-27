#!/usr/bin/env bash
# Build one harness file into a goto binary and check one or more of its
# harness functions with CBMC.
#
#   run.sh <harness> <function>... [-- extra cbmc args]
#
# <harness> names harness/<harness>.c; harness/<harness>.srcs lists the
# xquic sources it links (one per line, @XQUIC@ and @HERE@ expanded).
#
# Environment:
#   XQUIC    xquic source tree      (default: this checkout)
#   CBMCBIN  directory of cbmc, goto-cc and goto-instrument (default:
#            from PATH)
#   MAXLEN   input bound in bytes   (default 64)
#   UNWIND   loop bound             (default MAXLEN + 2: the parser loops
#            consume at least one input byte per iteration)
#   CHECKS   full | core            (default full; core leaves out the
#            unsigned overflow, conversion and pointer-overflow checks)
#   DEFS     extra -D flags for the build
#   TAG      suffix of the goto binary, for builds with other DEFS/XQUIC
#   LOGDIR   directory for the full cbmc output of each function
#   RESTRICT goto-instrument --restrict-function-pointer argument(s),
#            comma-separated pointer_name/target pairs
#   NOBODY   comma-separated functions whose bodies goto-instrument removes
#            (cbmc then treats each call as returning any value)
#
# The whole script is one function, so editing this file while a run is in
# progress does not change the run.
main() {
  set -uo pipefail
  local here harness gb fn rc
  here=$(cd "$(dirname "$0")" && pwd)
  XQUIC=${XQUIC:-$(cd "$here/../.." && pwd)}
  if [ -z "${CBMCBIN:-}" ]; then
    CBMCBIN=$(dirname "$(command -v cbmc || echo /usr/bin/cbmc)")
  fi
  MAXLEN=${MAXLEN:-64}
  UNWIND=${UNWIND:-$((MAXLEN + 2))}
  CHECKS=${CHECKS:-full}
  DEFS=${DEFS:-}
  TAG=${TAG:-}

  harness=$1; shift
  local fns=()
  while [ $# -gt 0 ] && [ "$1" != -- ]; do fns+=("$1"); shift; done
  [ "${1:-}" = -- ] && shift

  mkdir -p "$here/build"
  gb="$here/build/$harness$TAG-$MAXLEN.gb"
  local srcs_a defs_a
  mapfile -t srcs_a < <(sed "s#@XQUIC@#$XQUIC#g; s#@HERE@#$here#g" \
                        "$here/harness/$harness.srcs")
  read -ra defs_a <<< "$DEFS"
  # rebuild when a harness, stub or xquic source is newer than the binary
  if [ ! -f "$gb" ] || [ -n "$(find -L "$here/harness" "$here/stubs" \
      "${srcs_a[@]}" -newer "$gb" 2>/dev/null | head -1)" ]; then
    if ! "$CBMCBIN/goto-cc" -I "$XQUIC" -I "$XQUIC/include" -I "$here/harness" \
        -DXQC_DISABLE_LOG -DMAXLEN="$MAXLEN" "${defs_a[@]}" \
        "$here/harness/$harness.c" "${srcs_a[@]}" -o "$gb.tmp"; then
      echo "goto-cc failed for $harness" >&2
      return 2
    fi
    mv "$gb.tmp" "$gb"
  fi
  if [ -n "${NOBODY:-}" ]; then
    local nargs=() f
    IFS=, read -ra fs <<< "$NOBODY"
    for f in "${fs[@]}"; do nargs+=(--remove-function-body "$f"); done
    "$CBMCBIN/goto-instrument" "${nargs[@]}" "$gb" "$gb.nobody" >/dev/null || return 2
    gb="$gb.nobody"
  fi
  if [ -n "${RESTRICT:-}" ]; then
    local rargs=() r
    IFS=, read -ra rs <<< "$RESTRICT"
    for r in "${rs[@]}"; do rargs+=(--restrict-function-pointer "$r"); done
    "$CBMCBIN/goto-instrument" "${rargs[@]}" "$gb" "$gb.restricted" >/dev/null || return 2
    gb="$gb.restricted"
  fi

  local checks=(--pointer-check --bounds-check --signed-overflow-check
                --undefined-shift-check --memory-leak-check --div-by-zero-check
                --pointer-primitive-check)
  if [ "$CHECKS" = full ]; then
    checks+=(--unsigned-overflow-check --conversion-check --pointer-overflow-check)
  fi

  rc=0
  for fn in "${fns[@]}"; do
    local start end secs out status summary verdict
    start=$(date +%s.%N)
    out=$("$CBMCBIN/cbmc" "$gb" --function "$fn" "${checks[@]}" \
          --malloc-may-fail --malloc-fail-null \
          --unwind "$UNWIND" --unwinding-assertions --drop-unused-functions \
          "$@" 2>&1)
    status=$?
    end=$(date +%s.%N)
    secs=$(awk -v a="$start" -v b="$end" 'BEGIN { printf "%.1f", b - a }')
    summary=$(printf '%s\n' "$out" | grep -E '^\*\* [0-9]+ of [0-9]+ failed' | tail -1)
    verdict=$(printf '%s\n' "$out" | grep -E '^VERIFICATION (SUCCESSFUL|FAILED)' | tail -1)
    [ -n "$verdict" ] || verdict="ERROR(status $status)"
    printf '%-34s %-24s %7ss  %s\n' "$fn" "${verdict#VERIFICATION }" "$secs" "$summary"
    printf '%s\n' "$out" | grep -E ': FAILURE$' | sed 's/^/    /'
    [ $status -eq 0 ] || rc=$status
    if [ -n "${LOGDIR:-}" ]; then
      mkdir -p "$LOGDIR"; printf '%s\n' "$out" > "$LOGDIR/$harness$TAG-$fn.log"
    fi
  done
  return $rc
}
main "$@"
exit $?
