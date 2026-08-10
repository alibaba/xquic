#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "open3"
require "yaml"

root = ARGV.shift || abort("usage: architecture_check.rb <repo-root> [--ownership|--parallel-selftest|--legacy-equivalence|--all]")
modes = ARGV.empty? ? ["--all"] : ARGV
base_ref = ENV.fetch("CASE_TEST_BASE_REF", "origin/main")

def run!(env, *cmd)
  output, status = Open3.capture2e(env, *cmd)
  raise "command failed: #{cmd.join(" ")}\n#{output}" unless status.success?

  output
end

def case_names(text)
  static_names = text.scan(/case_print_result\s+"([^"]+)"/).flatten.reject { |name| name.include?("$") }
  dynamic_names = text.scan(/wrong_direction_stream_case\s+\d+\s+"([^"]+)"/).flatten

  static_names + dynamic_names.flat_map { |name| [name, name] }
end

def anchored_body(text)
  anchor = text.index("clear_log() {")
  raise "missing clear_log anchor" unless anchor

  text[anchor..]
end

def legacy_equivalence_body(text)
  anchored_body(text).sub(
    /^# issues #565.*?^killall test_server 2> \/dev\/null\n\n/m,
    ""
  )
end

def parse_key_values(text)
  text.lines.each_with_object({}) do |line, values|
    key, value = line.chomp.split("=", 2)
    values[key] = value if value
  end
end

def ownership(root)
  output = run!({}, "bash", File.join(root, "scripts/case_test.sh"), "--inventory")
  values = parse_key_values(output)

  unless values["legacy_total"] == values["matched_total"]
    raise "legacy ownership is incomplete\n#{output}"
  end

  unless values["unmatched_total"] == "0"
    raise "legacy ownership has unmatched cases\n#{output}"
  end

  unless values["repeated_total"] == "0"
    raise "legacy ownership has repeated cases\n#{output}"
  end

  puts "ownership=pass"
  puts "legacy_total=#{values.fetch("legacy_total")}"
  puts "matched_total=#{values.fetch("matched_total")}"
  puts "unmatched_total=#{values.fetch("unmatched_total")}"
  puts "repeated_total=#{values.fetch("repeated_total")}"
end

def generated_shard_coverage(root)
  build_dir = File.join(root, "build/validation")
  work_dir = File.join(build_dir, "case_test_generate_check")
  FileUtils.rm_rf(work_dir)
  FileUtils.mkdir_p(work_dir)

  runner_map = run!({}, "bash", File.join(root, "scripts/case_test.sh"), "--runners")
  generated = []
  runner_map.each_line do |line|
    group_id, runner, port_offset = line.chomp.split("\t")
    next if group_id == "observability.qlog"

    shard_work_dir = File.join(work_dir, group_id.tr(".", "_"))
    FileUtils.mkdir_p(shard_work_dir)
    env = {
      "XQC_BUILD_DIR" => build_dir,
      "CASE_TEST_WORK_DIR" => shard_work_dir,
      "CASE_TEST_PORT" => (18_000 + port_offset.to_i).to_s,
      "CASE_TEST_SHARD_ID" => group_id.tr(".", "_"),
      "CASE_TEST_GENERATE_ONLY" => "1"
    }
    script_path = run!(env, "bash", File.join(root, runner)).lines.last.to_s.chomp
    raise "missing generated script for #{group_id}: #{script_path}" unless File.file?(script_path)

    run!({}, "bash", "-n", script_path)
    names = case_names(File.read(script_path)).uniq
    puts "generated_group=#{group_id} legacy_count=#{names.length}"
    generated.concat(names.map { |name| [name, group_id] })
  end

  qlog_path = File.join(root, "case_test/observability/qlog.sh")
  run!({}, "bash", "-n", qlog_path)
  generated.concat(case_names(File.read(qlog_path)).uniq.map { |name| [name, "observability.qlog"] })

  legacy_names = case_names(File.read(File.join(root, "case_test/legacy/full_suite.sh"))).uniq
  owners = Hash.new { |hash, key| hash[key] = [] }
  generated.each { |name, group_id| owners[name] << group_id }
  missing = legacy_names - owners.keys
  repeated = owners.select { |_name, group_ids| group_ids.length > 1 }

  raise "generated shard coverage has missing cases: #{missing.inspect}" unless missing.empty?
  raise "generated shard coverage has repeated cases: #{repeated.inspect}" unless repeated.empty?

  puts "generated_shard_coverage=pass"
  puts "generated_total=#{owners.length}"
  puts "legacy_total=#{legacy_names.length}"
  puts "missing=0"
  puts "repeated=0"
end

def parallel_selftest(root)
  work_dir = File.join(root, "build/case_test_arch_check")
  FileUtils.rm_rf(work_dir)
  FileUtils.mkdir_p(work_dir)

  trace_path = File.join(work_dir, "trace.log")
  legacy_path = File.join(work_dir, "legacy.sh")
  manifest_path = File.join(work_dir, "manifest.yml")

  groups = %w[selftest.alpha selftest.beta selftest.gamma]
  groups.each do |group_id|
    runner_path = File.join(work_dir, "#{group_id.tr(".", "_")}.sh")
    File.write(runner_path, <<~SH)
      #!/bin/bash
      set -euo pipefail
      printf 'start\\t#{group_id}\\t%s\\t%s\\t%s\\n' "${CASE_TEST_PORT}" "${CASE_TEST_WORK_DIR}" "$(date +%s)" >> #{trace_path}
      sleep 1
      printf 'end\\t#{group_id}\\t%s\\t%s\\t%s\\n' "${CASE_TEST_PORT}" "${CASE_TEST_WORK_DIR}" "$(date +%s)" >> #{trace_path}
    SH
    FileUtils.chmod("+x", runner_path)
  end

  File.write(legacy_path, groups.map { |group_id| "case_print_result \"#{group_id}\" \"pass\"\n" }.join)
  manifest = {
    "version" => 1,
    "groups" => groups.map do |group_id|
      {
        "id" => group_id,
        "module" => "common",
        "source_paths" => ["README.md"],
        "runner" => "build/case_test_arch_check/#{group_id.tr(".", "_")}.sh",
        "execution" => "implemented",
        "port_offset" => groups.index(group_id),
        "owned_legacy_name_patterns" => [Regexp.escape(group_id)]
      }
    end
  }
  File.write(manifest_path, manifest.to_yaml)

  started_at = Time.now
  output = run!(
    {
      "CASE_TEST_MANIFEST" => manifest_path,
      "CASE_TEST_LEGACY_SUITE" => legacy_path,
      "CASE_TEST_PORT_BASE" => "19000"
    },
    "bash", File.join(root, "scripts/case_test.sh"),
    "--execute", "--parallel", "--jobs", "3", "--module", "common"
  )
  elapsed = Time.now - started_at
  trace = File.read(trace_path).lines.map { |line| line.chomp.split("\t") }

  starts = trace.select { |fields| fields[0] == "start" }
  ends = trace.select { |fields| fields[0] == "end" }
  ports = starts.map { |fields| fields[2] }
  work_dirs = starts.map { |fields| fields[3] }
  first_end_index = trace.index { |fields| fields[0] == "end" }
  starts_before_first_end = trace[0...first_end_index].count { |fields| fields[0] == "start" }

  raise "expected 3 starts, got #{starts.length}\n#{trace.inspect}" unless starts.length == 3
  raise "expected 3 ends, got #{ends.length}\n#{trace.inspect}" unless ends.length == 3
  raise "ports are not unique: #{ports.inspect}" unless ports.uniq.length == 3
  raise "work dirs are not unique: #{work_dirs.inspect}" unless work_dirs.uniq.length == 3
  unless first_end_index && starts_before_first_end > 1
    raise "runners did not overlap before first completion\n#{trace.inspect}"
  end

  puts "parallel_selftest=pass"
  puts "elapsed_seconds=#{format("%.3f", elapsed)}"
  puts "scheduled_groups=#{groups.length}"
  puts "starts_before_first_end=#{starts_before_first_end}"
  puts "ports=#{ports.join(",")}"
  puts output
end

def parallel_failure_selftest(root)
  work_dir = File.join(root, "build/case_test_arch_check_fail")
  FileUtils.rm_rf(work_dir)
  FileUtils.mkdir_p(work_dir)

  legacy_path = File.join(work_dir, "legacy.sh")
  manifest_path = File.join(work_dir, "manifest.yml")

  {
    "selftest.pass" => "pass",
    "selftest.fail" => "fail"
  }.each do |group_id, result|
    runner_path = File.join(work_dir, "#{group_id.tr(".", "_")}.sh")
    File.write(runner_path, <<~SH)
      #!/bin/bash
      source #{File.join(root, "case_test/lib/common.sh").inspect}
      case_print_result "#{group_id}" "#{result}"
      exit 0
    SH
    FileUtils.chmod("+x", runner_path)
  end

  File.write(
    legacy_path,
    "case_print_result \"selftest.pass\" \"pass\"\n" \
      "case_print_result \"selftest.fail\" \"fail\"\n"
  )
  manifest = {
    "version" => 1,
    "groups" => [
      {
        "id" => "selftest.pass",
        "module" => "common",
        "source_paths" => ["README.md"],
        "runner" => "build/case_test_arch_check_fail/selftest_pass.sh",
        "execution" => "implemented",
        "port_offset" => 0,
        "owned_legacy_name_patterns" => ["selftest\\.pass"]
      },
      {
        "id" => "selftest.fail",
        "module" => "common",
        "source_paths" => ["README.md"],
        "runner" => "build/case_test_arch_check_fail/selftest_fail.sh",
        "execution" => "implemented",
        "port_offset" => 1,
        "owned_legacy_name_patterns" => ["selftest\\.fail"]
      }
    ]
  }
  File.write(manifest_path, manifest.to_yaml)

  output, status = Open3.capture2e(
    {
      "CASE_TEST_MANIFEST" => manifest_path,
      "CASE_TEST_LEGACY_SUITE" => legacy_path,
      "CASE_TEST_PORT_BASE" => "19100"
    },
    "bash", File.join(root, "scripts/case_test.sh"),
    "--execute", "--parallel", "--jobs", "2", "--module", "common"
  )

  raise "failure selftest unexpectedly passed\n#{output}" if status.success?
  unless output.include?("[case-test] selftest.fail result=fail") &&
      output.include?("[     FAIL ] xquic_case_test.selftest.fail")
    raise "failure selftest did not report failed case\n#{output}"
  end

  puts "parallel_failure_selftest=pass"
end

def legacy_equivalence(root, base_ref)
  base_text = run!({}, "git", "-C", root, "show", "#{base_ref}:scripts/case_test.sh")
  current_text = File.read(File.join(root, "case_test/legacy/full_suite.sh"))
  base_names = case_names(base_text)
  current_names = case_names(current_text)

  unless base_names == current_names
    missing = base_names - current_names
    added = current_names - base_names
    raise "legacy case names differ: missing=#{missing.inspect} added=#{added.inspect}"
  end

  unless legacy_equivalence_body(base_text) == legacy_equivalence_body(current_text)
    raise "legacy suite body differs after clear_log anchor"
  end

  wrapper_text = File.read(File.join(root, "scripts/case_test.sh"))
  runner_text = File.read(File.join(root, "case_test/lib/runner.sh"))
  unless wrapper_text.include?("case_test/lib/runner.sh") &&
      runner_text.include?("case_test/legacy/full_suite.sh")
    raise "compatibility entry point does not dispatch to the legacy full suite"
  end

  puts "legacy_equivalence=pass"
  puts "base_ref=#{base_ref}"
  puts "case_result_lines=#{current_names.length}"
  puts "unique_case_count=#{current_names.uniq.length}"
  puts "body_anchor=clear_log"
end

if modes.include?("--all") || modes.include?("--ownership")
  ownership(root)
end

if modes.include?("--all") || modes.include?("--generated-shard-coverage")
  generated_shard_coverage(root)
end

if modes.include?("--all") || modes.include?("--parallel-selftest")
  parallel_selftest(root)
end

if modes.include?("--all") || modes.include?("--parallel-failure-selftest")
  parallel_failure_selftest(root)
end

if modes.include?("--all") || modes.include?("--legacy-equivalence")
  legacy_equivalence(root, base_ref)
end
