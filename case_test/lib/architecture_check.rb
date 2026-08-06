#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "open3"
require "yaml"

root = ARGV.shift || abort("usage: architecture_check.rb <repo-root> [--parallel-selftest|--legacy-equivalence|--all]")
modes = ARGV.empty? ? ["--all"] : ARGV
base_ref = ENV.fetch("CASE_TEST_BASE_REF", "origin/main")

def run!(env, *cmd)
  output, status = Open3.capture2e(env, *cmd)
  raise "command failed: #{cmd.join(" ")}\n#{output}" unless status.success?

  output
end

def case_names(text)
  text.scan(/case_print_result\s+"([^"]+)"/).flatten
end

def anchored_body(text)
  anchor = text.index("clear_log() {")
  raise "missing clear_log anchor" unless anchor

  text[anchor..]
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
        "legacy_name_patterns" => [Regexp.escape(group_id)]
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

  unless anchored_body(base_text) == anchored_body(current_text)
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

if modes.include?("--all") || modes.include?("--parallel-selftest")
  parallel_selftest(root)
end

if modes.include?("--all") || modes.include?("--legacy-equivalence")
  legacy_equivalence(root, base_ref)
end
