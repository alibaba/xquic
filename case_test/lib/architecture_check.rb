#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "open3"
require "yaml"

root = ARGV.shift || abort("usage: architecture_check.rb <repo-root> [--ownership|--runner-syntax|--parallel-selftest|--run-dir-selftest|--case-filter-run-dir-selftest|--case-filter-missing-selftest|--event-dedupe-selftest|--coverage-mismatch-selftest|--build-gate-selftest|--parallel-budget-selftest|--parallel-failure-selftest|--case-timeout-selftest|--background-fd-selftest|--all]")
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
  forbidden_helper_defs = [
    /^\s*(?:function\s+)?(?:clear_log|grep_err_log|case_print_result)\s*\(\s*\)/,
    /^\s*(?:BUILD_DIR|CASE_TEST_WORK_DIR|CASE_TEST_PORT_ARG|CLIENT_BIN|SERVER_BIN)=/,
    /^#!\/bin\/bash/
  ]

  manifest.fetch("groups").each do |group|
    runner = File.join(root, group.fetch("runner"))
    lines = File.readlines(runner)
    violations = []
    lines.each_with_index do |line, index|
      line_number = index + 1
      next if line_number == 1 && line.start_with?("#!/bin/bash")
      next unless forbidden_helper_defs.any? { |pattern| line.match?(pattern) }

      violations << "#{group.fetch("runner")}:#{line_number}:#{line.strip}"
    end

    discovery_index = lines.rindex { |line| line.include?("if case_test_is_discovery; then") }
    if discovery_index.nil?
      violations << "#{group.fetch("runner")}: missing case_test_is_discovery entrypoint"

    else
      allowed_entrypoint = [
        /^if case_test_is_discovery; then$/,
        /^case_test_run$/,
        /^exit 0$/,
        /^fi$/,
        /^if \[\[ "\$\{CASE_TEST_GENERATE_ONLY:-0\}" = "1" \]\]; then$/,
        /^case_test_enter_work_dir$/,
        /^trap 'case_test_stop_server; case_test_cleanup_udp_port' EXIT$/,
        /^case_test_require_sudo$/
      ]

      lines[(discovery_index + 1)..].to_a.each_with_index do |line, offset|
        stripped = line.strip
        next if stripped.empty?
        next if allowed_entrypoint.any? { |pattern| stripped.match?(pattern) }

        line_number = discovery_index + offset + 2
        violations << "#{group.fetch("runner")}:#{line_number}:unexpected entrypoint statement: #{stripped}"
      end
    end

    unless violations.empty?
      raise "runner violates native runner structure:\n#{violations.join("\n")}"
    end

    run!({}, "bash", "-n", runner)
    names = native_cases(root, group)
    names.each do |name|
      if name.include?(",")
        raise "case names must not contain commas because runner maps use comma-separated case filters: #{group.fetch("id")}:#{name}"
      end
    end
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
    case_test_case #{group_id.inspect} --id native --mode self-reporting --run selftest_run
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

def run_dir_selftest(root)
  work_dir = File.join(root, "build/case_test_arch_check_run_dir")
  FileUtils.rm_rf(work_dir)
  FileUtils.mkdir_p(work_dir)

  trace_path = File.join(work_dir, "trace.log")
  manifest_path = File.join(work_dir, "manifest.yml")
  runner_path = File.join(work_dir, "selftest_same_group.sh")
  write_selftest_runner(runner_path, root, "selftest.same_group", trace_path)

  manifest = {
    "version" => 1,
    "groups" => [
      {
        "id" => "selftest.same_group",
        "module" => "common",
        "source_paths" => ["README.md"],
        "runner" => "build/case_test_arch_check_run_dir/selftest_same_group.sh",
        "execution" => "implemented",
        "port_offset" => 0
      }
    ]
  }
  File.write(manifest_path, manifest.to_yaml)

  outputs = [File.join(work_dir, "run1.out"), File.join(work_dir, "run2.out")]
  pids = [
    Process.spawn(
      {
        "CASE_TEST_MANIFEST" => manifest_path,
        "CASE_TEST_PORT_BASE" => "19500"
      },
      "bash", File.join(root, "scripts/case_test.sh"),
      "--execute", "--module", "common",
      out: outputs[0],
      err: [:child, :out]
    ),
    Process.spawn(
      {
        "CASE_TEST_MANIFEST" => manifest_path,
        "CASE_TEST_PORT_BASE" => "19600"
      },
      "bash", File.join(root, "scripts/case_test.sh"),
      "--execute", "--module", "common",
      out: outputs[1],
      err: [:child, :out]
    )
  ]
  statuses = pids.map { |pid| Process.wait2(pid).last }
  combined = outputs.map { |path| File.read(path) }.join("\n")
  failed = statuses.reject(&:success?)
  raise "run-dir selftest command failed\n#{combined}" unless failed.empty?

  trace = File.read(trace_path).lines.map { |line| line.chomp.split("\t") }
  starts = trace.select { |fields| fields[0] == "start" }
  work_dirs = starts.map { |fields| fields[3] }

  raise "expected two starts, got #{starts.length}\n#{trace.inspect}" unless starts.length == 2
  raise "concurrent invocations reused a work dir: #{work_dirs.inspect}\n#{combined}" unless work_dirs.uniq.length == 2

  puts "run_dir_selftest=pass"
  puts "work_dirs=#{work_dirs.join(",")}"
end

def case_filter_run_dir_selftest(root)
  work_dir = File.join(root, "build/case_test_arch_check_case_run_dir")
  FileUtils.rm_rf(work_dir)
  FileUtils.mkdir_p(work_dir)

  trace_path = File.join(work_dir, "trace.log")
  manifest_path = File.join(work_dir, "manifest.yml")
  runner_path = File.join(work_dir, "selftest_cases.sh")
  File.write(runner_path, <<~SH)
    #!/bin/bash
    set -u
    source #{File.join(root, "case_test/lib/common.sh").inspect}
    case_test_group "selftest.case_run_dir"
    selftest_one()
    {
        printf 'case\\tone\\t%s\\n' "${CASE_TEST_WORK_DIR}" >> #{trace_path}
        echo "selftest.one ...>>>>>>>> pass:1"
        case_print_result "selftest.one" "pass"
    }
    selftest_two()
    {
        printf 'case\\ttwo\\t%s\\n' "${CASE_TEST_WORK_DIR}" >> #{trace_path}
        echo "selftest.two ...>>>>>>>> pass:1"
        case_print_result "selftest.two" "pass"
    }
    case_test_case "selftest.one" --id native --mode self-reporting --run selftest_one
    case_test_case "selftest.two" --id native --mode self-reporting --run selftest_two
    if case_test_is_discovery; then
        case_test_run
        exit 0
    fi
    case_test_run
  SH
  FileUtils.chmod("+x", runner_path)

  manifest = {
    "version" => 1,
    "groups" => [
      {
        "id" => "selftest.case_run_dir",
        "module" => "common",
        "source_paths" => ["README.md"],
        "runner" => "build/case_test_arch_check_case_run_dir/selftest_cases.sh",
        "execution" => "implemented",
        "port_offset" => 0
      }
    ]
  }
  File.write(manifest_path, manifest.to_yaml)

  output = run!(
    {
      "CASE_TEST_MANIFEST" => manifest_path,
      "CASE_TEST_PORT_BASE" => "19700"
    },
    "bash", File.join(root, "scripts/case_test.sh"),
    "--execute", "--group", "selftest.case_run_dir",
    "--case", "selftest.one", "--case", "selftest.two"
  )

  trace = File.read(trace_path).lines.map { |line| line.chomp.split("\t") }
  work_dirs = trace.select { |fields| fields[0] == "case" }.map { |fields| fields[2] }

  raise "expected two case work dirs, got #{work_dirs.length}\n#{trace.inspect}\n#{output}" unless work_dirs.length == 2
  raise "case filters reused a work dir: #{work_dirs.inspect}\n#{output}" unless work_dirs.uniq.length == 2
  unless output.include?("selftest.case_run_dir/selftest.one/case_test.log") &&
      output.include?("selftest.case_run_dir/selftest.two/case_test.log")
    raise "case-filter logs did not include per-case paths\n#{output}"
  end

  puts "case_filter_run_dir_selftest=pass"
  puts "case_filter_work_dirs=#{work_dirs.join(",")}"
end

def case_filter_missing_selftest(root)
  work_dir = File.join(root, "build/case_test_arch_check_case_missing")
  FileUtils.rm_rf(work_dir)
  FileUtils.mkdir_p(work_dir)

  manifest_path = File.join(work_dir, "manifest.yml")
  runner_path = File.join(work_dir, "selftest_case_missing.sh")
  File.write(runner_path, <<~SH)
    #!/bin/bash
    set -u
    source #{File.join(root, "case_test/lib/common.sh").inspect}
    case_test_group "selftest.case_missing"
    selftest_present()
    {
        echo "selftest.present ...>>>>>>>> pass:1"
        case_print_result "selftest.present" "pass"
    }
    case_test_case "selftest.present" --id native --mode self-reporting --run selftest_present
    if case_test_is_discovery; then
        case_test_run
        exit 0
    fi
    case_test_run
  SH
  FileUtils.chmod("+x", runner_path)

  manifest = {
    "version" => 1,
    "groups" => [
      {
        "id" => "selftest.case_missing",
        "module" => "common",
        "source_paths" => ["README.md"],
        "runner" => "build/case_test_arch_check_case_missing/selftest_case_missing.sh",
        "execution" => "implemented",
        "port_offset" => 0
      }
    ]
  }
  File.write(manifest_path, manifest.to_yaml)

  output, status = Open3.capture2e(
    {
      "CASE_TEST_MANIFEST" => manifest_path,
      "CASE_TEST_PORT_BASE" => "19900"
    },
    "bash", File.join(root, "scripts/case_test.sh"),
    "--execute", "--group", "selftest.case_missing",
    "--case", "selftest.present", "--case", "selftest.absent"
  )

  raise "missing case selftest unexpectedly passed\n#{output}" if status.success?
  unless output.include?("missing_case=selftest.absent")
    raise "missing case selftest did not expose the missing selector\n#{output}"
  end

  puts "case_filter_missing_selftest=pass"
end

def event_dedupe_selftest(root)
  work_dir = File.join(root, "build/case_test_arch_check_event_dedupe")
  FileUtils.rm_rf(work_dir)
  FileUtils.mkdir_p(work_dir)

  manifest_path = File.join(work_dir, "manifest.yml")
  runner_path = File.join(work_dir, "selftest_event_dedupe.sh")
  File.write(runner_path, <<~SH)
    #!/bin/bash
    set -u
    source #{File.join(root, "case_test/lib/common.sh").inspect}
    case_test_group "selftest.event_dedupe"
    selftest_run()
    {
        printf 'selftest.event\\tfail\\n' >> "${CASE_TEST_EVENT_FILE}"
        echo "selftest.event ...>>>>>>>> pass:1"
        case_print_result "selftest.event" "pass"
    }
    case_test_case "selftest.event" --id native --mode self-reporting --run selftest_run
    if case_test_is_discovery; then
        case_test_run
        exit 0
    fi
    case_test_run
  SH
  FileUtils.chmod("+x", runner_path)

  manifest = {
    "version" => 1,
    "groups" => [
      {
        "id" => "selftest.event_dedupe",
        "module" => "common",
        "source_paths" => ["README.md"],
        "runner" => "build/case_test_arch_check_event_dedupe/selftest_event_dedupe.sh",
        "execution" => "implemented",
        "port_offset" => 0
      }
    ]
  }
  File.write(manifest_path, manifest.to_yaml)

  output, status = Open3.capture2e(
    {
      "CASE_TEST_MANIFEST" => manifest_path,
      "CASE_TEST_PORT_BASE" => "19800"
    },
    "bash", File.join(root, "scripts/case_test.sh"),
    "--execute", "--module", "common"
  )

  raise "event dedupe selftest unexpectedly passed\n#{output}" if status.success?
  lines = output.lines.grep(/\[case-test:selftest\.event_dedupe\] selftest\.event >>>>>>>> pass:/)
  raise "expected one normalized event line, got #{lines.length}\n#{output}" unless lines.length == 1
  raise "fail event did not win over duplicate pass\n#{output}" unless lines.first.include?("pass:0")

  puts "event_dedupe_selftest=pass"
end

def coverage_mismatch_selftest(root)
  work_dir = File.join(root, "build/case_test_arch_check_coverage_mismatch")
  FileUtils.rm_rf(work_dir)
  FileUtils.mkdir_p(work_dir)

  manifest_path = File.join(work_dir, "manifest.yml")
  runner_path = File.join(work_dir, "selftest_coverage_mismatch.sh")
  File.write(runner_path, <<~SH)
    #!/bin/bash
    set -u
    source #{File.join(root, "case_test/lib/common.sh").inspect}
    case_test_group "selftest.coverage_mismatch"
    selftest_one()
    {
        echo "selftest.one ...>>>>>>>> pass:1"
        case_print_result "selftest.one" "pass"
    }
    selftest_two()
    {
        return 0
    }
    case_test_case "selftest.one" --id native --mode self-reporting --run selftest_one
    case_test_case "selftest.two" --id native --run selftest_two
    if case_test_is_discovery; then
        case_test_run
        exit 0
    fi
    CASE_TEST_CASE="selftest.one"
    case_test_run
  SH
  FileUtils.chmod("+x", runner_path)

  manifest = {
    "version" => 1,
    "groups" => [
      {
        "id" => "selftest.coverage_mismatch",
        "module" => "common",
        "source_paths" => ["README.md"],
        "runner" => "build/case_test_arch_check_coverage_mismatch/selftest_coverage_mismatch.sh",
        "execution" => "implemented",
        "port_offset" => 0
      }
    ]
  }
  File.write(manifest_path, manifest.to_yaml)

  output, status = Open3.capture2e(
    {
      "CASE_TEST_MANIFEST" => manifest_path,
      "CASE_TEST_PORT_BASE" => "19920"
    },
    "bash", File.join(root, "scripts/case_test.sh"),
    "--execute", "--module", "common"
  )

  raise "coverage mismatch selftest unexpectedly passed\n#{output}" if status.success?
  unless output.include?("coverage-mismatch expected=2 actual=1")
    raise "coverage mismatch selftest did not expose expected/actual counts\n#{output}"
  end

  puts "coverage_mismatch_selftest=pass"
end

def build_gate_selftest(root)
  work_dir = File.join(root, "build/case_test_arch_check_build_gate")
  FileUtils.rm_rf(work_dir)
  FileUtils.mkdir_p(work_dir)

  manifest_path = File.join(work_dir, "manifest.yml")
  build_dir = File.join(work_dir, "build_without_cache")
  normal_runner = File.join(work_dir, "selftest_normal.sh")
  gated_runner = File.join(work_dir, "selftest_gated.sh")
  write_selftest_runner(normal_runner, root, "selftest.normal")
  write_selftest_runner(gated_runner, root, "selftest.gated")

  manifest = {
    "version" => 1,
    "max_parallel_jobs" => 2,
    "groups" => [
      {
        "id" => "selftest.normal",
        "module" => "common",
        "source_paths" => ["README.md"],
        "runner" => "build/case_test_arch_check_build_gate/selftest_normal.sh",
        "execution" => "implemented",
        "port_offset" => 0
      },
      {
        "id" => "selftest.gated",
        "module" => "common",
        "feature" => "selftest_feature",
        "requires_cmake" => ["XQC_ENABLE_SELFTEST_FEATURE"],
        "source_paths" => ["README.md"],
        "runner" => "build/case_test_arch_check_build_gate/selftest_gated.sh",
        "execution" => "implemented",
        "port_offset" => 1
      }
    ]
  }
  File.write(manifest_path, manifest.to_yaml)

  output = run!(
    {
      "CASE_TEST_MANIFEST" => manifest_path,
      "XQC_BUILD_DIR" => build_dir
    },
    "bash", File.join(root, "scripts/case_test.sh"),
    "--execution-plan"
  )
  values = parse_key_values(output)

  unless values["implemented_unique_cases"] == "1" &&
      output.include?("implemented_group=selftest.normal case_count=1") &&
      output.include?("skipped_build_group=selftest.gated case_count=1")
    raise "build-gated group was not skipped without CMake evidence\n#{output}"
  end

  output, status = Open3.capture2e(
    {
      "CASE_TEST_MANIFEST" => manifest_path,
      "XQC_BUILD_DIR" => build_dir
    },
    "bash", File.join(root, "scripts/case_test.sh"),
    "--execution-plan", "--group", "selftest.gated"
  )

  raise "explicit build-gated group unexpectedly passed\n#{output}" if status.success?
  unless output.include?("unsupported_group=selftest.gated") &&
      output.include?("requires_cmake=XQC_ENABLE_SELFTEST_FEATURE")
    raise "explicit build-gated group did not expose unsupported reason\n#{output}"
  end

  FileUtils.mkdir_p(build_dir)
  File.write(File.join(build_dir, "CMakeCache.txt"), <<~CACHE)
    XQC_ENABLE_SELFTEST_FEATURE:BOOL=ON
  CACHE

  output = run!(
    {
      "CASE_TEST_MANIFEST" => manifest_path,
      "XQC_BUILD_DIR" => build_dir
    },
    "bash", File.join(root, "scripts/case_test.sh"),
    "--execution-plan"
  )
  values = parse_key_values(output)

  unless values["implemented_unique_cases"] == "2" &&
      output.include?("implemented_group=selftest.normal case_count=1") &&
      output.include?("implemented_group=selftest.gated case_count=1") &&
      !output.include?("skipped_build_group=selftest.gated")
    raise "enabled build-gated group was not included with CMake evidence\n#{output}"
  end

  puts "build_gate_selftest=pass"
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
    case_test_case "selftest.timeout" --id native --mode self-reporting --run selftest_run
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

def background_fd_selftest(root)
  work_dir = File.join(root, "build/case_test_arch_check_background_fd")
  FileUtils.rm_rf(work_dir)
  FileUtils.mkdir_p(work_dir)

  manifest_path = File.join(work_dir, "manifest.yml")
  runner_path = File.join(work_dir, "selftest_background_fd.sh")
  File.write(runner_path, <<~SH)
    #!/bin/bash
    set -u
    source #{File.join(root, "case_test/lib/common.sh").inspect}
    case_test_group "selftest.background_fd"
    selftest_run()
    {
        case_test_start_server ruby -e 'trap("TERM") { exit 0 }; sleep 12'
        echo "selftest.background_fd ...>>>>>>>> pass:1"
        case_print_result "selftest.background_fd" "pass"
    }
    case_test_case "selftest.background_fd" --id native --mode self-reporting --run selftest_run
    if case_test_is_discovery; then
        case_test_run
        exit 0
    fi
    case_test_run
    case_test_stop_server
  SH
  FileUtils.chmod("+x", runner_path)

  manifest = {
    "version" => 1,
    "groups" => [
      {
        "id" => "selftest.background_fd",
        "module" => "common",
        "source_paths" => ["README.md"],
        "runner" => "build/case_test_arch_check_background_fd/selftest_background_fd.sh",
        "execution" => "implemented",
        "port_offset" => 0
      }
    ]
  }
  File.write(manifest_path, manifest.to_yaml)

  started_at = Time.now
  output = run!(
    {
      "CASE_TEST_MANIFEST" => manifest_path,
      "CASE_TEST_PORT_BASE" => "19400"
    },
    "bash", File.join(root, "scripts/case_test.sh"),
    "--execute", "--module", "common"
  )
  elapsed = Time.now - started_at

  unless output.include?("[case-test:selftest.background_fd] selftest.background_fd >>>>>>>> pass:1")
    raise "background fd selftest did not report pass\n#{output}"
  end
  raise "background fd selftest waited for background output fd\n#{output}" if elapsed >= 8

  puts "background_fd_selftest=pass"
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

if modes.include?("--all") || modes.include?("--run-dir-selftest")
  run_dir_selftest(root)
end

if modes.include?("--all") || modes.include?("--case-filter-run-dir-selftest")
  case_filter_run_dir_selftest(root)
end

if modes.include?("--all") || modes.include?("--case-filter-missing-selftest")
  case_filter_missing_selftest(root)
end

if modes.include?("--all") || modes.include?("--event-dedupe-selftest")
  event_dedupe_selftest(root)
end

if modes.include?("--all") || modes.include?("--coverage-mismatch-selftest")
  coverage_mismatch_selftest(root)
end

if modes.include?("--all") || modes.include?("--build-gate-selftest")
  build_gate_selftest(root)
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

if modes.include?("--all") || modes.include?("--background-fd-selftest")
  background_fd_selftest(root)
end
