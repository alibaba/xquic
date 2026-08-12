#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"
require "open3"

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
manifest = YAML.load_file(manifest_path)

def discover_native_cases(root, group)
  env = {
    "CASE_TEST_DISCOVER" => "1",
    "CASE_TEST_GROUP" => group.fetch("id").to_s,
    "CASE_TEST_MODULE" => group.fetch("module").to_s,
    "CASE_TEST_FEATURE" => group.fetch("feature", "").to_s
  }
  runner = File.join(root, group.fetch("runner"))
  output, status = Open3.capture2e(env, "bash", runner)
  abort "case-test discovery failed for #{group.fetch("id")}:\n#{output}" unless status.success?

  output.each_line.each_with_object([]) do |line, native_cases|
    fields = line.chomp.split("\t")
    next unless fields[0] == "native_case"

    native_cases << {
      "group" => fields[1],
      "module" => fields[2],
      "feature" => fields[3],
      "name" => fields[4],
      "id" => fields[5]
    }
  end
end

groups = manifest.fetch("groups").map do |group|
  native_cases = discover_native_cases(root, group)
  names = native_cases.map { |native_case| native_case.fetch("name") }.uniq.sort
  group.merge("case_names" => names, "native_cases" => native_cases)
end

if options[:inventory]
  matched_by = Hash.new { |hash, key| hash[key] = [] }
  groups.each do |group|
    group.fetch("case_names", []).each do |name|
      matched_by[name] << group.fetch("id")
    end
  end

  repeated = matched_by.select { |_name, owners| owners.length > 1 }.sort

  puts "case_total=#{matched_by.length}"
  puts "matched_total=#{matched_by.length}"
  puts "unmatched_total=0"
  puts "repeated_total=#{repeated.length}"
  puts ""
  repeated.each do |name, owners|
    puts "repeated=#{name} groups=#{owners.sort.join(',')}"
  end
  exit repeated.empty? ? 0 : 3
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
      wanted == group["id"] || group.fetch("case_names", []).include?(wanted)
    end
  end
end

if selected.empty? && !options[:list]
  warn "no matching case-test groups"
  exit 1
end

if options[:execution_plan]
  selected_cases = selected.flat_map { |group| group.fetch("case_names", []) }.uniq.sort
  implemented = selected.select { |group| group.fetch("execution", "pending") == "implemented" }
  implemented_cases = implemented.flat_map { |group| group.fetch("case_names", []) }.uniq.sort
  pending = selected.reject { |group| group.fetch("execution", "pending") == "implemented" }
  missing = selected_cases - implemented_cases
  max_parallel_jobs = manifest.fetch("max_parallel_jobs", implemented.length)
  max_safe_jobs = missing.empty? ? [max_parallel_jobs, implemented.length].min : 1
  max_safe_jobs = 1 if max_safe_jobs < 1

  puts "selected_groups=#{selected.length}"
  puts "implemented_groups=#{implemented.length}"
  puts "pending_groups=#{pending.length}"
  puts "selected_unique_cases=#{selected_cases.length}"
  puts "implemented_unique_cases=#{implemented_cases.length}"
  puts "missing_unique_cases=#{missing.length}"
  puts "complete=#{missing.empty?}"
  puts "max_safe_jobs=#{max_safe_jobs}"
  implemented.sort_by { |group| group.fetch("id") }.each do |group|
    puts "implemented_group=#{group.fetch("id")} case_count=#{group.fetch("case_names", []).length}"
  end
  pending.sort_by { |group| group.fetch("id") }.each do |group|
    puts "pending_group=#{group.fetch("id")} case_count=#{group.fetch("case_names", []).length}"
  end
  exit missing.empty? ? 0 : 3
end

if options[:runners]
  selected.
    select { |group| group.fetch("execution", "pending") == "implemented" }.
    sort_by { |group| group.fetch("id") }.
    each do |group|
      puts [
        group.fetch("id"),
        group.fetch("runner"),
        group.fetch("port_offset"),
        group.fetch("module"),
        group.fetch("feature", "")
      ].join("\t")
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
  puts "case_count=#{group.fetch("case_names").length}"
  group.fetch("native_cases", []).each do |native_case|
    puts "native_case=#{native_case.fetch("name")} id=#{native_case.fetch("id")}"
  end
  group.fetch("case_names").each do |name|
    puts "case_name=#{name}"
  end
end
