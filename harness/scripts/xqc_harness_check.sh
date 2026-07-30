#!/bin/bash
#
# Static checks for repository-owned agent harness routing drift.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FAILURES=0

pass()
{
    echo "PASS: $*"
}

fail()
{
    echo "FAIL: $*" >&2
    FAILURES=$((FAILURES + 1))
}

require_file()
{
    local path="$1"

    if [[ -f "${ROOT_DIR}/${path}" ]]; then
        pass "found ${path}"
    else
        fail "missing ${path}"
    fi
}

require_grep()
{
    local pattern="$1"
    local path="$2"
    local label="$3"

    if grep -Eq -- "${pattern}" "${ROOT_DIR}/${path}"; then
        pass "${label}"
    else
        fail "${label}"
    fi
}

require_line_count()
{
    local path="$1"
    local min_lines="$2"
    local max_lines="$3"
    local label="$4"
    local lines

    lines="$(wc -l < "${ROOT_DIR}/${path}")"
    lines="${lines//[[:space:]]/}"

    if [[ "${lines}" -ge "${min_lines}" && "${lines}" -le "${max_lines}" ]]; then
        pass "${label} (${lines} lines)"
    else
        fail "${label} (${lines} lines, expected ${min_lines}-${max_lines})"
    fi
}

require_manifest_schema()
{
    local output

    if output="$(ruby "${ROOT_DIR}/harness/scripts/harness_manifest_check.rb" "${ROOT_DIR}")"; then
        pass "${output}"
    else
        echo "${output}" >&2
        fail "manifest schema is invalid"
    fi
}

require_skill_schema()
{
    local output

    if output="$(ruby - "${ROOT_DIR}" <<'RUBY'
root = ARGV.fetch(0)
skills_dir = File.join(root, "harness/skills")
errors = []
skills = Dir.glob(File.join(skills_dir, "*/SKILL.md")).sort

errors << "harness/skills must contain at least one skill" if skills.empty?

skills.each do |skill_file|
  skill_dir = File.basename(File.dirname(skill_file))
  text = File.read(skill_file)

  unless text.start_with?("---\n")
    errors << "#{skill_file.sub(root + "/", "")} must start with YAML front matter"
    next
  end

  front_matter = text.split(/^---\s*$/, 3)[1].to_s
  name = front_matter[/^name:\s*([^\n]+)\s*$/, 1].to_s.strip
  description = front_matter[/^description:\s*([^\n]+)\s*$/, 1].to_s.strip

  errors << "#{skill_dir}: front matter name must match directory" unless name == skill_dir
  errors << "#{skill_dir}: description is required" if description.empty?
  errors << "#{skill_dir}: description must include a Use when trigger" unless description.include?("Use when")
  if description.length > 420
    errors << "#{skill_dir}: description is too long (#{description.length}, max 420)"
  end
  if text.lines.length > 180
    errors << "#{skill_dir}: skill body is too long (#{text.lines.length}, max 180)"
  end
end

if errors.empty?
  puts "skill schema ok (#{skills.length} skills)"
  exit 0
end

errors.each { |error| warn error }
exit 1
RUBY
    )"; then
        pass "${output}"
    else
        echo "${output}" >&2
        fail "skill schema is invalid"
    fi
}

reject_tree_grep()
{
    local pattern="$1"
    local label="$2"
    local matches

    matches="$(
        grep -RInE "${pattern}" \
            "${ROOT_DIR}/AGENTS.md" \
            "${ROOT_DIR}/harness" \
            "${ROOT_DIR}/.github/workflows" 2>/dev/null \
        | grep -vF "${ROOT_DIR}/harness/scripts/xqc_harness_check.sh:" || true
    )"

    if [[ -n "${matches}" ]]; then
        echo "${matches}" >&2
        fail "${label}"
    else
        pass "${label}"
    fi
}

check_optional_claude_adapter()
{
    local path="${ROOT_DIR}/CLAUDE.md"

    if [[ ! -f "${path}" ]]; then
        pass "CLAUDE.md adapter is not committed"
        return
    fi

    require_grep "harness/" "CLAUDE.md" \
        "CLAUDE.md points back to repository harness sources"

    if grep -Eq "docs_ai/harness_manifest.yml|\\.claude/skills" "${path}"; then
        fail "CLAUDE.md must not depend on docs_ai manifest or .claude skills"
    else
        pass "CLAUDE.md does not depend on docs_ai manifest or .claude skills"
    fi
}

require_file "AGENTS.md"
require_file "harness/README.md"
require_file "harness/ai_docs/README.md"
require_file "harness/ai_docs/structure_map.md"
require_file "harness/ai_docs/change_map.md"
require_file "harness/ai_docs/behavior_specs.md"
require_file "harness/ai_docs/decision_records.md"
require_file "harness/spec/PROJECT_INSTRUCTIONS.md"
require_file "harness/spec/doc-style.md"
require_file "harness/spec/run-artifacts.md"
require_file "harness/spec/harness-manifest.yml"
require_file "harness/spec/openspec.md"
require_file "harness/skills/harness-review/SKILL.md"
require_file "harness/skills/validate/SKILL.md"
require_file "harness/scripts/setup_harness.sh"
require_file "harness/scripts/hooks/pre-push"
require_file "harness/scripts/harness_trace.sh"
require_file "harness/scripts/harness_manifest_check.rb"
require_file "scripts/validate.sh"

require_line_count "AGENTS.md" 60 100 \
    "AGENTS remains bounded as the strong injection layer"
require_grep "harness/spec/harness-manifest.yml" \
    "AGENTS.md" \
    "AGENTS points to harness manifest"
require_grep "harness/ai_docs/README.md" \
    "AGENTS.md" \
    "AGENTS points to AI docs for harness structure changes"
require_grep "harness/spec/doc-style.md" \
    "AGENTS.md" \
    "AGENTS points to documentation style guidance"
require_grep "OpenSpec" \
    "AGENTS.md" \
    "AGENTS documents OpenSpec long-task routing"
require_grep "harness/spec/harness-manifest.yml" \
    "scripts/validate.sh" \
    "validate script reads feature profiles from the manifest"
require_grep "--feature" \
    "scripts/validate.sh" \
    "validate script exposes a generic feature profile option"
require_grep "build/harness/runs/<task-id>" \
    "harness/spec/run-artifacts.md" \
    "run artifact contract defines canonical task evidence directory"
require_manifest_schema
require_grep "harness/scripts/xqc_harness_check.sh" \
    ".github/workflows/build.yml" \
    "GitHub workflow runs harness check"
require_skill_schema
check_optional_claude_adapter

reject_tree_grep "docs_ai/harness_manifest.yml|\\.claude/skills" \
    "committed harness does not depend on docs_ai manifest or .claude skills"

echo ""
if [[ "${FAILURES}" -eq 0 ]]; then
    echo "Harness check: PASS"
else
    echo "Harness check: FAIL (${FAILURES} issue(s))" >&2
    exit 1
fi
