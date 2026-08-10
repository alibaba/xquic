#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"

root = ARGV.shift || abort("missing repository root")
args = ARGV.dup

options = {
  list: false,
  dry_run: false,
  inventory: false,
  runners: false,
  execution_plan: false,
  groups: [],
  cases: [],
  modules: [],
  features: [],
  paths: []
}

until args.empty?
  arg = args.shift
  case arg
  when "--list"
    options[:list] = true
  when "--dry-run"
    options[:dry_run] = true
  when "--inventory"
    options[:inventory] = true
  when "--runners"
    options[:runners] = true
  when "--execution-plan"
    options[:execution_plan] = true
  when "--group"
    options[:groups] << (args.shift || abort("--group requires a value"))
  when "--case"
    options[:cases] << (args.shift || abort("--case requires a value"))
  when "--module"
    options[:modules] << (args.shift || abort("--module requires a value"))
  when "--feature"
    options[:features] << (args.shift || abort("--feature requires a value"))
  when "--from-path"
    options[:paths] << (args.shift || abort("--from-path requires a value"))
  when "-h", "--help"
    puts "usage: scripts/case_test.sh [--list] [--inventory] [--dry-run] [--runners] [--execution-plan] [--group <id>] [--case <id-or-name>] [--module <name>] [--feature <name>] [--from-path <path>]"
    exit 0
  else
    abort("unknown case_test selector: #{arg}")
  end
end

manifest_path = ENV.fetch("CASE_TEST_MANIFEST", File.join(root, "case_test/manifest.yml"))
script_path = ENV.fetch("CASE_TEST_LEGACY_SUITE", File.join(root, "case_test/legacy/full_suite.sh"))
manifest = YAML.load_file(manifest_path)
legacy_names = File.read(script_path).
  scan(/case_print_result\s+"([^"]+)"/).
  flatten.
  uniq.
  sort

groups = manifest.fetch("groups").map do |group|
  patterns = group.fetch("owned_legacy_name_patterns", []).map { |pattern| Regexp.new("\\A(?:#{pattern})\\z") }
  names = legacy_names.select { |name| patterns.any? { |pattern| pattern.match?(name) } }
  group.merge("legacy_names" => names)
end

if options[:inventory]
  matched_by = Hash.new { |hash, key| hash[key] = [] }
  groups.each do |group|
    group.fetch("legacy_names", []).each do |name|
      matched_by[name] << group.fetch("id")
    end
  end

  unmatched = legacy_names.reject { |name| matched_by.key?(name) }.sort
  repeated = matched_by.select { |_name, owners| owners.length > 1 }.sort

  puts "legacy_total=#{legacy_names.length}"
  puts "matched_total=#{matched_by.length}"
  puts "unmatched_total=#{unmatched.length}"
  puts "repeated_total=#{repeated.length}"
  puts ""
  repeated.each do |name, owners|
    puts "repeated=#{name} groups=#{owners.sort.join(',')}"
  end
  puts ""
  unmatched.each do |name|
    puts "unmatched=#{name}"
  end
  exit repeated.empty? && unmatched.empty? ? 0 : 3
end

def path_matches?(path, pattern)
  File.fnmatch?(pattern, path, File::FNM_PATHNAME | File::FNM_EXTGLOB)
end

selected = groups
selected = selected.select { |group| options[:groups].include?(group["id"].to_s) } unless options[:groups].empty?
selected = selected.select { |group| options[:modules].include?(group["module"].to_s) } unless options[:modules].empty?
selected = selected.select { |group| options[:features].include?(group["feature"].to_s) } unless options[:features].empty?

unless options[:paths].empty?
  selected = selected.select do |group|
    source_paths = group.fetch("source_paths", [])
    options[:paths].any? do |path|
      source_paths.any? { |pattern| path_matches?(path, pattern.to_s) }
    end
  end
end

unless options[:cases].empty?
  selected = selected.select do |group|
    options[:cases].any? do |wanted|
      wanted == group["id"] || group.fetch("legacy_names", []).include?(wanted)
    end
  end
end

if selected.empty? && !options[:list]
  warn "no matching case-test groups"
  exit 1
end

if options[:execution_plan]
  selected_legacy = selected.flat_map { |group| group.fetch("legacy_names", []) }.uniq.sort
  implemented = selected.select { |group| group.fetch("execution", "pending") == "implemented" }
  implemented_legacy = implemented.flat_map { |group| group.fetch("legacy_names", []) }.uniq.sort
  pending = selected.reject { |group| group.fetch("execution", "pending") == "implemented" }
  missing = selected_legacy - implemented_legacy

  puts "selected_groups=#{selected.length}"
  puts "implemented_groups=#{implemented.length}"
  puts "pending_groups=#{pending.length}"
  puts "selected_unique_cases=#{selected_legacy.length}"
  puts "implemented_unique_cases=#{implemented_legacy.length}"
  puts "missing_unique_cases=#{missing.length}"
  puts "complete=#{missing.empty?}"
  puts "max_safe_jobs=#{missing.empty? ? [implemented.length, 1].max : 1}"
  implemented.sort_by { |group| group.fetch("id") }.each do |group|
    puts "implemented_group=#{group.fetch("id")} legacy_count=#{group.fetch("legacy_names", []).length}"
  end
  pending.sort_by { |group| group.fetch("id") }.each do |group|
    puts "pending_group=#{group.fetch("id")} legacy_count=#{group.fetch("legacy_names", []).length}"
  end
  exit missing.empty? ? 0 : 3
end

if options[:runners]
  selected.
    select { |group| group.fetch("execution", "pending") == "implemented" }.
    sort_by { |group| group.fetch("id") }.
    each do |group|
      puts "#{group.fetch("id")}\t#{group.fetch("runner")}\t#{group.fetch("port_offset")}"
    end
  exit 0
end

puts "mode=#{options[:list] ? "list" : "dry-run"}"
puts "selected_execution=#{selected.any? { |group| group.fetch("execution", "pending") == "implemented" } ? "partial" : "pending"}"
selected.sort_by { |group| group.fetch("id") }.each do |group|
  puts ""
  puts "case_group=#{group.fetch("id")}"
  puts "module=#{group.fetch("module")}"
  puts "submodule=#{group["submodule"]}" if group["submodule"]
  puts "feature=#{group["feature"]}" if group["feature"]
  puts "status=#{group["status"]}" if group["status"]
  puts "execution=#{group.fetch("execution", "pending")}"
  puts "runner=#{group.fetch("runner")}"
  puts "port_offset=#{group.fetch("port_offset")}"
  puts "legacy_count=#{group.fetch("legacy_names").length}"
  group.fetch("legacy_names").each do |name|
    puts "legacy_name=#{name}"
  end
end
