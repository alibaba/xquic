#!/usr/bin/env bash
# Copyright (c) 2026, Alibaba Group Holding Limited
#
# Count the instructions that the xqc_bench scenarios execute in the XQUIC
# sources, and compare them with the counts of tests/bench/baseline.txt.
#
# Each scenario runs once under valgrind's cachegrind (--cache-sim=no). The
# benchmark runs on a virtual clock and a seeded loss pattern, so a build
# executes the same instructions in the XQUIC sources on every run, give or
# take a few when a connection ID, which the library draws from
# /dev/urandom, shares a hash bucket with another. The script sums the
# instructions whose debug information points into src/ or include/; the
# C library, BoringSSL and the benchmark itself are left out, so the counts
# depend neither on the CPU that runs them nor on the random numbers of the
# TLS handshake. They do depend on the compiler: compare builds made with
# the same compiler and flags as the baseline.
#
# usage: scripts/perf_bench.sh [--update] [--tolerance <percent>] <build-dir>
#
#   --update        write the measured counts into the baseline file
#   --tolerance P   allowed difference from the baseline, in percent
#                   (default 1)
#
# Environment:
#   XQC_PERF_BASELINE   baseline file (default tests/bench/baseline.txt)
#   XQC_PERF_BENCH      benchmark program
#                       (default <build-dir>/tests/xqc_bench)
#   XQC_PERF_OUT        directory for the cachegrind outputs
#                       (default <build-dir>/perf_bench)
#   XQC_PERF_KEY, XQC_PERF_CERT
#                       server key and certificate (default server.key and
#                       server.crt in <build-dir>)
#   GITHUB_STEP_SUMMARY when set, a Markdown table is appended to it
#
# Exit status: 0 when every scenario is within the tolerance, 1 when one is
# not, 2 on a usage or run error.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
update=0
tolerance=1

usage()
{
    sed -n '4,/^$/{s/^# \{0,1\}//;p}' "${BASH_SOURCE[0]}" >&2
    exit 2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --update) update=1; shift ;;
        --tolerance)
            [[ $# -ge 2 && "$2" =~ ^[0-9]+([.][0-9]+)?$ ]] || usage
            tolerance="$2"; shift 2 ;;
        -h|--help) usage ;;
        -*) usage ;;
        *) break ;;
    esac
done
[[ $# -eq 1 ]] || usage

build_dir="$(cd "$1" && pwd -P)"
bench="${XQC_PERF_BENCH:-${build_dir}/tests/xqc_bench}"
baseline="${XQC_PERF_BASELINE:-${ROOT_DIR}/tests/bench/baseline.txt}"
out_dir="${XQC_PERF_OUT:-${build_dir}/perf_bench}"
key="${XQC_PERF_KEY:-${build_dir}/server.key}"
cert="${XQC_PERF_CERT:-${build_dir}/server.crt}"

for f in "${bench}" "${baseline}" "${key}" "${cert}"; do
    if [[ ! -f "${f}" ]]; then
        echo "perf_bench: ${f} not found" >&2
        exit 2
    fi
done
if ! command -v valgrind > /dev/null 2>&1; then
    echo "perf_bench: valgrind not found" >&2
    exit 2
fi
mkdir -p "${out_dir}"

# Sum the Ir of the lines whose file is under src/ or include/.
count_xquic()
{
    awk -v src="${ROOT_DIR}/src/" -v inc="${ROOT_DIR}/include/" '
        /^fl=/ {
            # resolve the "dir/.." steps of paths relative to the build tree
            f = substr($0, 4)
            while (sub(/\/[^\/]+\/\.\.\//, "/", f)) {
            }
            mine = (index(f, src) == 1 || index(f, inc) == 1)
            next
        }
        /^summary:/ { total = $2; next }
        /^[0-9]/ { if (mine) sum += $2; next }
        END { printf "%d %d\n", sum, total }
    ' "$1"
}

failed=0
new_baseline="$(mktemp)"
trap 'rm -f "${new_baseline}"' EXIT
table="| Scenario | Baseline | Measured | Change | Total |"$'\n'
table+="|---|---:|---:|---:|---:|"$'\n'

printf '%-14s %14s %14s %9s %14s\n' scenario baseline measured change total

while IFS= read -r line || [[ -n "${line}" ]]; do
    if [[ -z "${line//[[:space:]]/}" || "${line}" =~ ^[[:space:]]*# ]]; then
        printf '%s\n' "${line}" >> "${new_baseline}"
        continue
    fi
    read -r name expected args <<< "${line}"
    if [[ ! "${expected}" =~ ^[0-9]+$ ]]; then
        echo "perf_bench: bad baseline line: ${line}" >&2
        exit 2
    fi

    out="${out_dir}/${name}.cachegrind"
    # shellcheck disable=SC2086
    if ! valgrind --tool=cachegrind --cache-sim=no \
            --cachegrind-out-file="${out}" \
            "${bench}" -k "${key}" -K "${cert}" ${args} \
            > "${out_dir}/${name}.log" 2>&1; then
        echo "perf_bench: scenario ${name} failed:" >&2
        cat "${out_dir}/${name}.log" >&2
        exit 2
    fi
    read -r measured total <<< "$(count_xquic "${out}")"

    change="$(awk -v m="${measured}" -v e="${expected}" 'BEGIN {
        if (e == 0) print "new"; else printf "%+.2f%%", (m - e) * 100 / e }')"
    status="$(awk -v m="${measured}" -v e="${expected}" -v t="${tolerance}" \
        'BEGIN { d = m - e; if (d < 0) d = -d
                 print (e > 0 && d * 100 <= t * e) ? "ok" : "off" }')"

    printf '%-14s %14d %14d %9s %14d\n' "${name}" "${expected}" \
        "${measured}" "${change}" "${total}"
    table+="| ${name} | ${expected} | ${measured} | ${change} | ${total} |"
    table+=$'\n'
    printf '%-14s %12d  %s\n' "${name}" "${measured}" "${args}" \
        >> "${new_baseline}"

    if [[ "${status}" != ok ]]; then
        failed=1
        if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
            echo "::error::${name}: ${measured} instructions in the XQUIC" \
                "sources, ${expected} in the baseline (${change})"
        fi
    fi
done < "${baseline}"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
        echo "### Instructions executed in the XQUIC sources"
        echo
        echo "Tolerance: ${tolerance}%. Total counts every instruction" \
            "of the run, for information."
        echo
        printf '%s' "${table}"
    } >> "${GITHUB_STEP_SUMMARY}"
fi

if [[ "${update}" -eq 1 ]]; then
    cp "${new_baseline}" "${baseline}"
    echo "perf_bench: updated ${baseline}"
    exit 0
fi

if [[ "${failed}" -ne 0 ]]; then
    echo "perf_bench: a scenario is more than ${tolerance}% away from" \
        "its baseline. If the change is expected, run" \
        "scripts/perf_bench.sh --update <build-dir> and commit" \
        "tests/bench/baseline.txt." >&2
    exit 1
fi
echo "perf_bench: every scenario is within ${tolerance}% of its baseline"
