#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "open3"
require "yaml"

root = ARGV.shift || abort("usage: architecture_check.rb <repo-root> [--ownership|--runner-syntax|--parallel-selftest|--parallel-budget-selftest|--parallel-failure-selftest|--case-timeout-selftest|--all]")
modes = ARGV.empty? ? ["--all"] : ARGV

def run!(env, *cmd)
  output, status = Open3.capture2e(env, *cmd)
  raise "command failed: #{cmd.join(" ")}\n#{output}" unless status.success?

  output
end

def parse_key_values(text)
  text.lines.each_with_object({}) do |line, values|
    key, value = line.chomp.split("=", 2)
    values[key] = value if value
  end
end

def native_cases(root, group)
  output = run!(
    {
      "CASE_TEST_DISCOVER" => "1",
      "CASE_TEST_GROUP" => group.fetch("id").to_s,
      "CASE_TEST_MODULE" => group.fetch("module").to_s,
      "CASE_TEST_FEATURE" => group.fetch("feature", "").to_s
    },
    "bash", File.join(root, group.fetch("runner"))
  )

  output.lines.each_with_object([]) do |line, cases|
    fields = line.chomp.split("\t")
    next unless fields[0] == "native_case"

    cases << fields[4]
  end
end

def ownership(root)
  output = run!({}, "bash", File.join(root, "scripts/case_test.sh"), "--inventory")
  values = parse_key_values(output)

  unless values["unmatched_total"] == "0"
    raise "native ownership has unmatched cases\n#{output}"
  end

  unless values["repeated_total"] == "0"
    raise "native ownership has repeated cases\n#{output}"
  end

  puts "ownership=pass"
  puts "case_total=#{values.fetch("case_total")}"
  puts "matched_total=#{values.fetch("matched_total")}"
  puts "unmatched_total=#{values.fetch("unmatched_total")}"
  puts "repeated_total=#{values.fetch("repeated_total")}"
end

def runner_syntax(root)
  manifest = YAML.load_file(File.join(root, "case_test/manifest.yml"))
  owners = Hash.new { |hash, key| hash[key] = [] }

  manifest.fetch("groups").each do |group|
    runner = File.join(root, group.fetch("runner"))
    run!({}, "bash", "-n", runner)
    names = native_cases(root, group)
    names.each { |name| owners[name] << group.fetch("id") }
    puts "runner=#{group.fetch("id")} case_count=#{names.length}"
  end

  repeated = owners.select { |_name, group_ids| group_ids.length > 1 }
  raise "native case registrations are repeated: #{repeated.inspect}" unless repeated.empty?

  puts "runner_syntax=pass"
  puts "registered_cases=#{owners.length}"
end

def write_selftest_runner(path, root, group_id, trace_path = nil, result: "pass")
  body = if trace_path
    <<~SH
      selftest_run()
      {
          printf 'start\\t#{group_id}\\t%s\\t%s\\t%s\\n' "${CASE_TEST_PORT}" "${CASE_TEST_WORK_DIR}" "$(date +%s)" >> #{trace_path}
          sleep 1
          printf 'end\\t#{group_id}\\t%s\\t%s\\t%s\\n' "${CASE_TEST_PORT}" "${CASE_TEST_WORK_DIR}" "$(date +%s)" >> #{trace_path}
          echo "#{group_id} ...>>>>>>>> pass:1"
          case_print_result "#{group_id}" "pass"
      }
    SH
  else
    <<~SH
      selftest_run()
      {
          echo "#{group_id} ...>>>>>>>> pass:#{result == "pass" ? "1" : "0"}"
          case_print_result "#{group_id}" "#{result}"
      }
    SH
  end

  File.write(path, <<~SH)
    #!/bin/bash
    set -u
    source #{File.join(root, "case_test/lib/common.sh").inspect}
    case_test_group #{group_id.inspect}
    case_test_case #{group_id.inspect} --id legacy --mode self-reporting --run selftest_run
    if case_test_is_discovery; then
        case_test_run
        exit 0
    fi
    #{body}
    case_test_run
  SH
  FileUtils.chmod("+x", path)
end

def parallel_selftest(root)
  work_dir = File.join(root, "build/case_test_arch_check")
  FileUtils.rm_rf(work_dir)
  FileUtils.mkdir_p(work_dir)

  trace_path = File.join(work_dir, "trace.log")
  manifest_path = File.join(work_dir, "manifest.yml")
  groups = %w[selftest.alpha selftest.beta selftest.gamma]

  groups.each do |group_id|
    runner_path = File.join(work_dir, "#{group_id.tr(".", "_")}.sh")
    write_selftest_runner(runner_path, root, group_id, trace_path)
  end

  manifest = {
    "version" => 1,
    "groups" => groups.map do |group_id|
      {
        "id" => group_id,
        "module" => "common",
        "source_paths" => ["README.md"],
        "runner" => "build/case_test_arch_check/#{group_id.tr(".", "_")}.sh",
        "execution" => "implemented",
        "port_offset" => groups.index(group_id)
      }
    end
  }
  File.write(manifest_path, manifest.to_yaml)

  started_at = Time.now
  output = run!(
    {
      "CASE_TEST_MANIFEST" => manifest_path,
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

  manifest_path = File.join(work_dir, "manifest.yml")
  groups = {
    "selftest.pass" => "pass",
    "selftest.fail" => "fail"
  }

  groups.each do |group_id, result|
    runner_path = File.join(work_dir, "#{group_id.tr(".", "_")}.sh")
    write_selftest_runner(runner_path, root, group_id, nil, result: result)
  end

  manifest = {
    "version" => 1,
    "groups" => groups.keys.map.with_index do |group_id, index|
      {
        "id" => group_id,
        "module" => "common",
        "source_paths" => ["README.md"],
        "runner" => "build/case_test_arch_check_fail/#{group_id.tr(".", "_")}.sh",
        "execution" => "implemented",
        "port_offset" => index
      }
    end
  }
  File.write(manifest_path, manifest.to_yaml)

  output, status = Open3.capture2e(
    {
      "CASE_TEST_MANIFEST" => manifest_path,
      "CASE_TEST_PORT_BASE" => "19100"
    },
    "bash", File.join(root, "scripts/case_test.sh"),
    "--execute", "--parallel", "--jobs", "2", "--module", "common"
  )

  raise "failure selftest unexpectedly passed\n#{output}" if status.success?
  unless output.include?("[case-test] selftest.fail result=fail") &&
      output.include?("[case-test:selftest.fail] selftest.fail >>>>>>>> pass:0")
    raise "failure selftest did not report failed case\n#{output}"
  end

  puts "parallel_failure_selftest=pass"
end

def case_timeout_selftest(root)
  work_dir = File.join(root, "build/case_test_arch_check_timeout")
  FileUtils.rm_rf(work_dir)
  FileUtils.mkdir_p(work_dir)

  manifest_path = File.join(work_dir, "manifest.yml")
  runner_path = File.join(work_dir, "selftest_timeout.sh")
  after_runner_path = File.join(work_dir, "selftest_after.sh")
  File.write(runner_path, <<~SH)
    #!/bin/bash
    set -u
    source #{File.join(root, "case_test/lib/common.sh").inspect}
    case_test_group "selftest.timeout"
    selftest_run()
    {
        sleep 5
        echo "selftest.timeout ...>>>>>>>> pass:1"
        case_print_result "selftest.timeout" "pass"
    }
    case_test_case "selftest.timeout" --id legacy --mode self-reporting --run selftest_run
    if case_test_is_discovery; then
        case_test_run
        exit 0
    fi
    case_test_run
  SH
  FileUtils.chmod("+x", runner_path)
  write_selftest_runner(after_runner_path, root, "selftest.after")

  manifest = {
    "version" => 1,
    "groups" => [
      {
        "id" => "selftest.timeout",
        "module" => "common",
        "source_paths" => ["README.md"],
        "runner" => "build/case_test_arch_check_timeout/selftest_timeout.sh",
        "execution" => "implemented",
        "port_offset" => 0
      },
      {
        "id" => "selftest.after",
        "module" => "common",
        "source_paths" => ["README.md"],
        "runner" => "build/case_test_arch_check_timeout/selftest_after.sh",
        "execution" => "implemented",
        "port_offset" => 1
      }
    ]
  }
  File.write(manifest_path, manifest.to_yaml)

  started_at = Time.now
  output, status = Open3.capture2e(
    {
      "CASE_TEST_MANIFEST" => manifest_path,
      "CASE_TEST_CASE_TIMEOUT" => "1",
      "CASE_TEST_SHARD_TIMEOUT" => "20",
      "CASE_TEST_PORT_BASE" => "19300"
    },
    "bash", File.join(root, "scripts/case_test.sh"),
    "--execute", "--module", "common"
  )
  elapsed = Time.now - started_at

  raise "timeout selftest unexpectedly passed\n#{output}" if status.success?
  raise "case timeout was not reported\n#{output}" unless output.include?("[case-test] case-timeout")
  raise "runner did not continue after timeout\n#{output}" unless output.include?("[case-test] selftest.after result=pass")
  raise "timeout selftest waited for shard timeout\n#{output}" if elapsed >= 8

  puts "case_timeout_selftest=pass"
  puts "elapsed_seconds=#{format("%.3f", elapsed)}"
end

def parallel_budget_selftest(root)
  work_dir = File.join(root, "build/case_test_arch_check_budget")
  FileUtils.rm_rf(work_dir)
  FileUtils.mkdir_p(work_dir)

  trace_path = File.join(work_dir, "trace.log")
  manifest_path = File.join(work_dir, "manifest.yml")
  groups = %w[
    selftest.alpha
    selftest.beta
    selftest.gamma
    selftest.delta
    selftest.epsilon
  ]

  groups.each do |group_id|
    runner_path = File.join(work_dir, "#{group_id.tr(".", "_")}.sh")
    write_selftest_runner(runner_path, root, group_id, trace_path)
  end

  manifest = {
    "version" => 1,
    "max_parallel_jobs" => 2,
    "groups" => groups.map.with_index do |group_id, index|
      {
        "id" => group_id,
        "module" => "common",
        "source_paths" => ["README.md"],
        "runner" => "build/case_test_arch_check_budget/#{group_id.tr(".", "_")}.sh",
        "execution" => "implemented",
        "port_offset" => index
      }
    end
  }
  File.write(manifest_path, manifest.to_yaml)

  output = run!(
    {
      "CASE_TEST_MANIFEST" => manifest_path,
      "CASE_TEST_PORT_BASE" => "19200"
    },
    "bash", File.join(root, "scripts/case_test.sh"),
    "--execute", "--parallel", "--jobs", "auto", "--module", "common"
  )

  trace = File.read(trace_path).lines.map { |line| line.chomp.split("\t") }
  active = 0
  max_active = 0
  saw_overlap = false
  trace.each do |fields|
    case fields[0]
    when "start"
      active += 1
      max_active = [max_active, active].max
      saw_overlap = true if active > 1
    when "end"
      active -= 1
    end
  end

  raise "parallel budget exceeded: max_active=#{max_active}\n#{trace.inspect}\n#{output}" if max_active > 2
  raise "parallel budget did not allow overlap\n#{trace.inspect}\n#{output}" unless saw_overlap
  raise "auto budget was not reported\n#{output}" unless output.include?("scheduling groups with jobs=2")

  puts "parallel_budget_selftest=pass"
  puts "max_active=#{max_active}"
end

if modes.include?("--all") || modes.include?("--ownership")
  ownership(root)
end

if modes.include?("--all") || modes.include?("--runner-syntax")
  runner_syntax(root)
end

if modes.include?("--all") || modes.include?("--parallel-selftest")
  parallel_selftest(root)
end

if modes.include?("--all") || modes.include?("--parallel-budget-selftest")
  parallel_budget_selftest(root)
end

if modes.include?("--all") || modes.include?("--parallel-failure-selftest")
  parallel_failure_selftest(root)
end

if modes.include?("--all") || modes.include?("--case-timeout-selftest")
  case_timeout_selftest(root)
end
