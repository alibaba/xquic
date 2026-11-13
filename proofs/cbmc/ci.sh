#!/usr/bin/env bash
# Run the proofs of proofs.list with the core checks (memory safety, signed
# overflow, shifts, leaks, division) and the assertions of the harnesses.
#
# Each line: <harness> <function> <maxlen> <pass|xfail> [VAR=value...]
# [-- cbmc options]. A proof marked "pass" must pass. One marked "xfail"
# fails on the current code until the change named in its comment is
# merged; the job warns once it passes, so that the mark can be flipped.
set -u
here=$(cd "$(dirname "$0")" && pwd)
failed=0
while read -r harness fn maxlen expect rest; do
  case "$harness" in ''|'#'*) continue ;; esac
  envs=()
  read -ra words <<< "$rest"
  while [ ${#words[@]} -gt 0 ] && [ "${words[0]}" != -- ]; do
    envs+=("${words[0]}")
    words=("${words[@]:1}")
  done
  [ ${#words[@]} -gt 0 ] && words=("${words[@]:1}")
  out=$(env CHECKS=core MAXLEN="$maxlen" "${envs[@]}" \
        "$here/run.sh" "$harness" "$fn" -- "${words[@]}" 2>&1)
  status=$?
  printf '%s\n' "$out"
  if [ "$expect" = pass ] && [ $status -ne 0 ]; then
    echo "::error::$harness $fn failed"
    failed=1
  elif [ "$expect" = xfail ] && [ $status -eq 0 ]; then
    echo "::warning::$harness $fn now passes: mark it pass in proofs/cbmc/proofs.list"
  fi
done < "$here/proofs.list"
exit $failed
