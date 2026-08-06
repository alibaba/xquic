#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"

root = ARGV.fetch(0)
manifest_path = File.join(root, "harness/spec/harness-manifest.yml")
errors = []

data = YAML.load_file(manifest_path)
cmake_text = File.read(File.join(root, "CMakeLists.txt"))
unit_main_path = File.join(root, "tests/unittest/main.c")
unit_main_text = File.exist?(unit_main_path) ? File.read(unit_main_path) : ""
cmake_options = cmake_text.scan(/^\s*option\s*\(\s*([A-Za-z0-9_]+)/).flatten
cunit_tests = unit_main_text.scan(/CU_add_test\s*\(\s*pSuite,\s*"([^"]+)"/).flatten

def require_hash(value, path, errors)
  errors << "#{path} must be a map" unless value.is_a?(Hash)
end

def require_nonempty_array(value, path, errors)
  unless value.is_a?(Array) && value.any?
    errors << "#{path} must be a non-empty list"
  end
end

def check_path_or_glob_exists(root, relative_path, path, errors)
  value = relative_path.to_s
  matches = if value.include?("*")
    Dir.glob(File.join(root, value))
  else
    [File.join(root, value)].select { |candidate| File.exist?(candidate) }
  end

  errors << "#{path} points to missing path or glob #{relative_path}" if matches.empty?
end

def route_features(modules)
  features = {}
  return features unless modules.is_a?(Hash)

  modules.each do |module_name, route|
    next unless route.is_a?(Hash)

    route.fetch("features", {}).each_key do |feature_name|
      features[feature_name.to_s] = module_name.to_s
    end
  end
  features
end

def validate_test_routing(root, data, errors)
  routing = data["test_routing"]
  return unless routing

  require_hash(routing, "test_routing", errors)
  return unless routing.is_a?(Hash)

  modules = data.fetch("modules", {})
  module_names = modules.is_a?(Hash) ? modules.keys.map(&:to_s) : []
  feature_owners = route_features(modules)

  case_manifest_path = routing["case_manifest"]
  legacy_full_suite_path = routing["case_legacy_full_suite"]
  check_file_exists(root, case_manifest_path, "test_routing.case_manifest", errors)
  check_file_exists(root, legacy_full_suite_path, "test_routing.case_legacy_full_suite", errors)

  if case_manifest_path && File.exist?(File.join(root, case_manifest_path.to_s))
    legacy_case_names = []
    if legacy_full_suite_path && File.exist?(File.join(root, legacy_full_suite_path.to_s))
      legacy_case_names = File.read(File.join(root, legacy_full_suite_path.to_s)).
        scan(/case_print_result\s+"([^"]+)"/).
        flatten.uniq
    end

    validate_case_manifest(
      root,
      File.join(root, case_manifest_path.to_s),
      module_names,
      feature_owners,
      legacy_case_names,
      errors
    )
  end
end

def validate_case_manifest(root, path, module_names, feature_owners, legacy_case_names, errors)
  manifest = YAML.load_file(path)
  relative = path.sub(root + "/", "")
  require_hash(manifest, relative, errors)
  return unless manifest.is_a?(Hash)

  errors << "#{relative}.version must be 1" unless manifest["version"] == 1
  groups = manifest["groups"]
  require_nonempty_array(groups, "#{relative}.groups", errors)
  return unless groups.is_a?(Array)

  ids = []
  groups.each_with_index do |group, index|
    group_path = "#{relative}.groups[#{index}]"
    require_hash(group, group_path, errors)
    next unless group.is_a?(Hash)

    id = group["id"].to_s
    ids << id
    errors << "#{group_path}.id is required" if id.empty?

    module_name = group["module"].to_s
    unless module_names.include?(module_name)
      errors << "#{group_path}.module references unknown module #{module_name}"
    end

    feature_name = group["feature"].to_s
    if !feature_name.empty? && feature_owners[feature_name] != module_name
      errors << "#{group_path}.feature references unknown feature #{feature_name} for module #{module_name}"
    end

    check_file_exists(root, group["runner"], "#{group_path}.runner", errors)
    require_nonempty_array(group["source_paths"], "#{group_path}.source_paths", errors)
    if group["source_paths"].is_a?(Array)
      group["source_paths"].each do |source_path|
        check_path_or_glob_exists(root, source_path, "#{group_path}.source_paths", errors)
      end
    end

    patterns = group["legacy_name_patterns"]
    status = group["status"].to_s
    execution = group.fetch("execution", "pending").to_s
    unless %w[pending implemented].include?(execution)
      errors << "#{group_path}.execution must be pending or implemented"
    end

    if status == "gap"
      errors << "#{group_path}.legacy_name_patterns must be a list" unless patterns.is_a?(Array)
      next
    end

    require_nonempty_array(patterns, "#{group_path}.legacy_name_patterns", errors)
    next unless patterns.is_a?(Array)

    matched = []
    patterns.each do |pattern|
      regexp = Regexp.new("\\A(?:#{pattern})\\z")
      matched.concat(legacy_case_names.select { |name| regexp.match?(name) })
    rescue RegexpError => e
      errors << "#{group_path}.legacy_name_patterns has invalid regexp #{pattern.inspect}: #{e.message}"
    end
    errors << "#{group_path}.legacy_name_patterns match no legacy cases" if matched.empty?
  end

  duplicate_ids = ids.group_by(&:itself).select { |_id, values| values.length > 1 }.keys
  errors << "#{relative}.groups has duplicate ids #{duplicate_ids.join(', ')}" unless duplicate_ids.empty?
end

def validate_validation(value, path, errors)
  require_hash(value, path, errors)
  return unless value.is_a?(Hash)

  unless value.key?("level") || value.key?("command")
    errors << "#{path} must define level or command"
  end

  errors << "#{path}.hints must be a list" if value.key?("hints") && !value["hints"].is_a?(Array)
  errors << "#{path}.unit must be a list" if value.key?("unit") && !value["unit"].is_a?(Array)
end

def check_file_exists(root, relative_path, path, errors)
  return if relative_path.to_s.include?("*")

  full_path = File.join(root, relative_path.to_s)
  errors << "#{path} points to missing file #{relative_path}" unless File.exist?(full_path)
end

def validate_route(name, route, path, errors, allow_missing_paths: false)
  errors << "#{path} uses ':' in key; use nested submodules/features instead" if name.to_s.include?(":")

  require_hash(route, path, errors)
  return unless route.is_a?(Hash)

  require_nonempty_array(route["paths"], "#{path}.paths", errors) unless allow_missing_paths
  validate_validation(route["validation"], "#{path}.validation", errors) if route.key?("validation")

  errors << "#{path}.read must be a list" if route.key?("read") && !route["read"].is_a?(Array)
  require_nonempty_array(route["feature_flags"], "#{path}.feature_flags", errors) if route.key?("feature_flags")

  %w[submodules features].each do |collection|
    next unless route.key?(collection)

    children = route[collection]
    require_hash(children, "#{path}.#{collection}", errors)
    next unless children.is_a?(Hash)

    children.each do |child_name, child_route|
      validate_route(child_name, child_route, "#{path}.#{collection}.#{child_name}", errors)
    end
  end
end

require_hash(data, "manifest", errors)

if data.is_a?(Hash)
  errors << "manifest version must be 3" unless data["version"] == 3
  require_hash(data["entrypoints"], "entrypoints", errors)
  require_hash(data["document_roles"], "document_roles", errors)
  require_hash(data["global_docs"], "global_docs", errors)
  require_hash(data["modules"], "modules", errors)
  require_hash(data["harness_layers"], "harness_layers", errors)

  if data["document_roles"].is_a?(Hash)
    expected_roles = {
      "specification" => {
        "authority" => "normative",
        "may_define_requirements" => true,
        "paths" => ["harness/spec/*"]
      },
      "documentation" => {
        "authority" => "informative",
        "may_define_requirements" => false,
        "paths" => ["harness/docs/*"]
      },
      "decision" => {
        "authority" => "rationale",
        "may_define_requirements" => false,
        "paths" => ["harness/decisions/*"]
      }
    }

    missing = expected_roles.keys - data["document_roles"].keys
    extra = data["document_roles"].keys - expected_roles.keys
    errors << "document_roles missing #{missing.join(', ')}" unless missing.empty?
    errors << "document_roles has unknown roles #{extra.join(', ')}" unless extra.empty?

    expected_roles.each do |role_name, expected|
      role = data["document_roles"][role_name]
      require_hash(role, "document_roles.#{role_name}", errors)
      next unless role.is_a?(Hash)

      expected.each do |field, value|
        unless role[field] == value
          errors << "document_roles.#{role_name}.#{field} must be #{value.inspect}"
        end
      end
    end
  end

  if data["harness_layers"].is_a?(Hash)
    expected_layers = %w[
      strong_injection
      on_demand_reading
      machine_mapping
      explanation
      self_check
      local_adapters
      private_extensions
    ]
    missing = expected_layers - data["harness_layers"].keys
    extra = data["harness_layers"].keys - expected_layers
    errors << "harness_layers missing #{missing.join(', ')}" unless missing.empty?
    errors << "harness_layers has unknown layers #{extra.join(', ')}" unless extra.empty?

    data["harness_layers"].each do |layer_name, layer|
      require_hash(layer, "harness_layers.#{layer_name}", errors)
      next unless layer.is_a?(Hash)

      if !layer.key?("files") && !layer.key?("examples")
        errors << "harness_layers.#{layer_name} must define files or examples"
      end
    end

    machine_mapping = data["harness_layers"]["machine_mapping"]
    if machine_mapping.is_a?(Hash)
      source = machine_mapping.dig("single_source_of_truth", "route_mapping")
      unless source == "harness/spec/harness-manifest.yml"
        errors << "harness_layers.machine_mapping.single_source_of_truth.route_mapping must be harness/spec/harness-manifest.yml"
      end
    end
  end

  if data["entrypoints"].is_a?(Hash)
    data["entrypoints"].each do |name, relative_path|
      check_file_exists(root, relative_path, "entrypoints.#{name}", errors)
    end
  end

  if data["global_docs"].is_a?(Hash)
    required_groups = %w[documentation decisions governance]
    missing_groups = required_groups - data["global_docs"].keys
    unless missing_groups.empty?
      errors << "global_docs missing #{missing_groups.join(', ')}"
    end

    data["global_docs"].each do |name, docs|
      require_nonempty_array(docs, "global_docs.#{name}", errors)
      next unless docs.is_a?(Array)

      docs.each do |relative_path|
        check_file_exists(root, relative_path, "global_docs.#{name}", errors)
      end
    end

    {
      "documentation" => "harness/docs/*.md",
      "decisions" => "harness/decisions/*.md"
    }.each do |group_name, pattern|
      listed = data["global_docs"][group_name]
      next unless listed.is_a?(Array)

      actual = Dir.glob(File.join(root, pattern)).
        map { |path| path.sub(root + "/", "") }.
        sort
      expected = listed.map(&:to_s).sort
      missing_from_manifest = actual - expected
      stale_manifest_docs = expected - actual
      unless missing_from_manifest.empty?
        errors << "global_docs.#{group_name} missing #{missing_from_manifest.join(', ')}"
      end
      unless stale_manifest_docs.empty?
        errors << "global_docs.#{group_name} lists missing #{stale_manifest_docs.join(', ')}"
      end
    end
  end

  if data["modules"].is_a?(Hash) && data["modules"].any?
    data["modules"].each do |module_name, module_route|
      validate_route(module_name, module_route, "modules.#{module_name}", errors)

      next unless module_route.is_a?(Hash)

      module_route.fetch("features", {}).each do |feature_name, feature_route|
        next unless feature_route.is_a?(Hash)

        feature_route.fetch("feature_flags", []).each do |flag|
          flag_name = flag.to_s.split("=", 2).first
          unless cmake_options.include?(flag_name)
            errors << "modules.#{module_name}.features.#{feature_name}.feature_flags lists unknown CMake option #{flag_name}"
          end
        end

        feature_route.fetch("validation", {}).fetch("unit", []).each do |unit_name|
          unless cunit_tests.include?(unit_name.to_s)
            errors << "modules.#{module_name}.features.#{feature_name}.validation.unit lists unknown CUnit test #{unit_name}"
          end
        end
      end
    end
  else
    errors << "modules must contain at least one module"
  end

  validate_test_routing(root, data, errors)

  errors << "top-level features are not allowed; nest features under their owning module" if data.key?("features")
end

if errors.empty?
  puts "manifest schema ok"
  exit 0
end

errors.each { |error| warn error }
exit 1
