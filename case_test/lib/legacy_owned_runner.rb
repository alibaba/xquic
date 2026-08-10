#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "yaml"

root = ARGV.fetch(0)
group_id = ARGV.fetch(1)

manifest = YAML.load_file(File.join(root, "case_test/manifest.yml"))
legacy_path = File.join(root, "case_test/legacy/full_suite.sh")
legacy_lines = File.readlines(legacy_path)
legacy_names = legacy_lines.join.scan(/case_print_result\s+"([^"]+)"/).flatten.uniq.sort

group = manifest.fetch("groups").find { |candidate| candidate.fetch("id") == group_id }
abort "unknown case-test group: #{group_id}" unless group

patterns = group.fetch("owned_legacy_name_patterns", []).map do |pattern|
  Regexp.new("\\A(?:#{pattern})\\z")
end
owned = legacy_names.select { |name| patterns.any? { |pattern| pattern.match?(name) } }.sort
abort "case-test group has no legacy cases: #{group_id}" if owned.empty?

def server_line?(line)
  line.include?("${SERVER_BIN}") && line.rstrip.end_with?("&")
end

def restart_line?(line)
  line.include?("killall test_server") || server_line?(line)
end

def transform_line(line)
  return "case_test_stop_server\n" if line.include?("killall test_server")

  if server_line?(line)
    stripped = line.rstrip.sub(/\s*&\s*(#.*)?\z/, "")
    return "case_test_start_server #{stripped}\n"
  end

  line.sub(/^(\s*)sudo\s+/, "\\1case_test_sudo ")
end

def setup_line?(line)
  stripped = line.strip
  return true if stripped.empty?
  return true if stripped.start_with?("#")
  return true if stripped.start_with?("rm -f ")
  return true if stripped.start_with?("rm -rf ")
  return true if stripped =~ /\Asleep\s+[0-9]+/
  return true if stripped.include?("killall test_server")

  server_line?(line)
end

def trailing_context_line?(line)
  stripped = line.strip
  return true if stripped.empty?
  return true if stripped.start_with?("#")
  return true if stripped == "fi"
  return true if stripped.start_with?("rm -f ")
  return true if stripped.start_with?("rm -rf ")

  false
end

blocks = []
previous_end = 0
consumed_until = -1
seen = {}
previous_case_owned = false
legacy_lines.each_with_index do |line, index|
  next if index <= consumed_until
  next unless line =~ /case_print_result\s+"([^"]+)"/

  name = Regexp.last_match(1)
  next if seen[[name, index]]

  block_end = index
  block_end += 1 while block_end < legacy_lines.length && legacy_lines[block_end] !~ /^\s*fi\s*$/
  next if block_end >= legacy_lines.length

  start = previous_end
  previous_end = block_end + 1
  consumed_until = block_end
  current_case_owned = owned.include?(name) && !seen[name]
  unless current_case_owned
    previous_case_owned = false
    next
  end

  setup_start = start
  unless previous_case_owned
    (start - 1).downto(0) do |candidate|
      if restart_line?(legacy_lines[candidate])
        setup_start = candidate
        setup_start -= 1 while setup_start > 0 && legacy_lines[setup_start - 1].include?("killall test_server")
        break
      end
    end
  end

  setup_end = start
  (setup_start...start).each do |candidate|
    if legacy_lines[candidate] =~ /^\s*clear_log\s*$/
      setup_end = candidate
      break
    end
  end

  setup = legacy_lines[setup_start...setup_end].select { |setup_line| setup_line?(setup_line) }
  trailer_end = block_end + 1
  trailer_end += 1 while trailer_end < legacy_lines.length && trailing_context_line?(legacy_lines[trailer_end])
  body = legacy_lines[start...trailer_end]
  blocks << [name, setup, body]
  seen[name] = true
  previous_case_owned = true
end

missing = owned - blocks.map(&:first)
abort "missing legacy case blocks for #{group_id}: #{missing.join(', ')}" unless missing.empty?

sudo_required = blocks.any? do |_name, setup, body|
  (setup + body).any? { |line| line =~ /^\s*sudo\s+/ }
end

def control_open?(line)
  line.strip.start_with?("if ")
end

def control_close?(line)
  line.strip == "fi"
end

def write_legacy_line(file, line, control_depth)
  if control_close?(line)
    return control_depth if control_depth.zero?

    file.write(transform_line(line))
    return control_depth - 1
  end

  file.write(transform_line(line))
  return control_depth + 1 if control_open?(line)

  control_depth
end

work_dir = ENV.fetch("CASE_TEST_WORK_DIR")
script_dir = File.join(work_dir, ".generated")
FileUtils.mkdir_p(script_dir)
script_path = File.join(script_dir, "#{group_id.tr('.', '_')}.sh")

File.open(script_path, "w", 0o755) do |file|
  file.puts "#!/bin/bash"
  file.puts "set -u"
  file.puts "ROOT_DIR=#{root.inspect}"
  file.puts "source \"${ROOT_DIR}/case_test/lib/common.sh\""
  file.puts "LOCAL_TEST=${CASE_TEST_LOCAL_TEST:-0}"
  file.puts "case_test_enter_work_dir"
  file.puts "trap case_test_stop_server EXIT"
  file.puts "rm -rf tp_localhost test_session xqc_token"
  file.puts "case_test_require_sudo" if sudo_required
  file.puts
  control_depth = 0
  blocks.each do |name, setup, body|
    file.puts "# legacy case: #{name}"
    (setup + body).each do |line|
      control_depth = write_legacy_line(file, line, control_depth)
    end
    file.puts
  end
  file.puts "case_test_stop_server"
end

if ENV["CASE_TEST_GENERATE_ONLY"] == "1"
  puts script_path
  exit 0
end

exec "/bin/bash", script_path
