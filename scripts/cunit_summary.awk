# Print "<total> <ran> <passed> <failed>" from the last "tests" row of the
# CUnit run summary in a unit test log, and nothing when the log has none.
# CTest prefixes each line of a test's output with "<test number>: ".
#
#   awk -f scripts/cunit_summary.awk <log>
{
    line = $0
    sub(/^[0-9]+:[[:space:]]*/, "", line)
    sub(/^[[:space:]]+/, "", line)
    field_count = split(line, fields, /[[:space:]]+/)
    is_summary = field_count == 6
    is_summary = is_summary && fields[1] == "tests"
    is_summary = is_summary && fields[2] ~ /^[0-9]+$/
    is_summary = is_summary && fields[3] ~ /^[0-9]+$/
    is_summary = is_summary && fields[4] ~ /^[0-9]+$/
    is_summary = is_summary && fields[5] ~ /^[0-9]+$/

    if (is_summary) {
        summary = fields[2] " " fields[3] " " fields[4] " " fields[5]
    }
}

END {
    if (summary != "") {
        print summary
    }
}
