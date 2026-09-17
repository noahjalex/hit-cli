#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "json"
require "pathname"
require "uri"
require "yaml"

ROOT = Pathname(__dir__).parent
METHODS = %w[get post put delete patch].freeze
PLATFORMS = {
  "direct-api" => {
    specs: Dir[ROOT.join("platforms/direct-api/openapi/reference/*.yaml")],
    base_url: "{{AFTERPAY_API_URL}}",
    headers: {
      "Accept" => "application/json",
      "Authorization" => "{{basicAuth AFTERPAY_MERCHANT_ID AFTERPAY_MERCHANT_SECRET}}"
    },
    auth: nil
  },
  "agency-api" => {
    specs: [ROOT.join("platforms/agency-api/openapi/Partner.yaml").to_s],
    base_url: "{{AGENCY_BASE_URL}}",
    headers: {"Accept" => "application/json"},
    auth: {
      "type" => "agency",
      "api_key_env" => "AGENCY_API_KEY",
      "secret_env" => "AGENCY_SHARED_SECRET"
    }
  },
  "cash-app-pay-partner-api" => {
    specs: Dir[ROOT.join("platforms/cash-app-pay-partner-api/openapi/*.yaml")].reject { |p| File.basename(p).include?("overrides") },
    base_url: "{{CASH_API_URL}}",
    headers: {"Accept" => "application/json"},
    auth: {
      "type" => "cash-app",
      "client_id_env" => "CASH_CLIENT_ID",
      "api_key_env" => "CASH_API_KEY",
      "api_secret_env" => "CASH_CLIENT_SECRET",
      "region_env" => "CASH_REGION"
    }
  }
}.freeze

$documents = {}

def load_yaml(path)
  path = File.expand_path(path)
  $documents[path] ||= YAML.unsafe_load_file(path)
end

def json_pointer(document, fragment)
  return document if fragment.nil? || fragment.empty?

  fragment.sub(%r{^/}, "").split("/").reduce(document) do |value, token|
    value.fetch(token.gsub("~1", "/").gsub("~0", "~"))
  end
end

def resolve(node, source_path)
  return node unless node.is_a?(Hash) && node["$ref"]

  file_part, fragment = node["$ref"].split("#", 2)
  target_path = file_part.empty? ? source_path : File.expand_path(file_part, File.dirname(source_path))
  json_pointer(load_yaml(target_path), fragment)
rescue Errno::ENOENT, KeyError
  node
end

def kebab(value)
  value.to_s
       .gsub(/([a-z0-9])([A-Z])/, "\\1-\\2")
       .gsub(/[^A-Za-z0-9]+/, "-")
       .gsub(/^-|-$/, "")
       .downcase
end

def api_group(path)
  kebab(File.basename(path).sub(/\.(v\d+\.)?ya?ml$/i, ""))
end

def server_prefix(spec)
  url = spec.fetch("servers", []).first&.fetch("url", "") || ""
  URI(url).path.sub(%r{/$}, "")
rescue URI::InvalidURIError
  ""
end

def parameters(path_item, operation, source_path)
  (path_item.fetch("parameters", []) + operation.fetch("parameters", [])).map do |parameter|
    resolve(parameter, source_path)
  end
end

def request_body(operation, source_path)
  resolve(operation["requestBody"], source_path) if operation["requestBody"]
end

def schema_example(schema, source_path, name = "value", seen = [])
  return nil unless schema

  if schema.is_a?(Hash) && schema["$ref"]
    identity = [source_path, schema["$ref"]]
    return "<#{name}>" if seen.include?(identity)

    file_part = schema["$ref"].split("#", 2).first
    next_source = file_part.empty? ? source_path : File.expand_path(file_part, File.dirname(source_path))
    return schema_example(resolve(schema, source_path), next_source, name, seen + [identity])
  end

  return schema["example"] if schema.key?("example")
  return schema["default"] if schema.key?("default")
  return schema["enum"].first if schema["enum"]&.any?

  variants = schema["oneOf"] || schema["anyOf"]
  return schema_example(variants.first, source_path, name, seen) if variants&.any?

  if schema["allOf"]
    return schema["allOf"].each_with_object({}) do |part, result|
      value = schema_example(part, source_path, name, seen)
      result.merge!(value) if value.is_a?(Hash)
    end
  end

  type = schema["type"] || (schema["properties"] ? "object" : nil)
  case type
  when "object"
    schema.fetch("properties", {}).to_h do |property_name, property_schema|
      [property_name, schema_example(property_schema, source_path, property_name, seen)]
    end
  when "array"
    [schema_example(schema["items"], source_path, name, seen)]
  when "integer", "number"
    0
  when "boolean"
    false
  else
    "<#{name}>"
  end
end

def content_summary(content)
  content.to_h.transform_values { |media| media.to_h["schema"] || {} }
end

def generate_platform(name, settings)
  platform_dir = ROOT.join("platforms", name)
  bodies_dir = platform_dir.join("bodies")
  FileUtils.rm_rf(bodies_dir)
  FileUtils.mkdir_p(bodies_dir)

  commands = {}
  catalog = {"platform" => name, "operations" => []}

  settings[:specs].sort.each do |source_path|
    spec = load_yaml(source_path)
    group = api_group(source_path)
    commands[group] ||= {}
    prefix = server_prefix(spec)

    spec.fetch("paths", {}).each do |path, raw_path_item|
      path_item = resolve(raw_path_item, source_path)
      METHODS.each do |method|
        next unless path_item[method]

        operation = path_item[method]
        operation_id = operation["operationId"] || "#{method}-#{path}"
        command_name = kebab(operation_id)
        params = parameters(path_item, operation, source_path)
        command_path = path.gsub(/\{([^}]+)\}/, ':\\1')
        required_query = params.select { |p| p["in"] == "query" && p["required"] }
        unless required_query.empty?
          command_path += "?" + required_query.map { |p| "#{p['name']}=:#{p['name']}" }.join("&")
        end

        headers = settings[:headers].dup
        body = request_body(operation, source_path)
        body_content = body&.fetch("content", {}) || {}
        headers["Content-Type"] = "application/json" if body_content.key?("application/json")

        commands[group][command_name] = {
          "method" => method.upcase,
          "url" => "#{settings[:base_url]}#{prefix}#{command_path}",
          "headers" => headers
        }
        commands[group][command_name]["auth"] = settings[:auth] if settings[:auth]

        body_template = nil
        if (json_body = body_content["application/json"])
          template = schema_example(json_body["schema"], source_path)
          body_path = bodies_dir.join(group, "#{command_name}.json")
          FileUtils.mkdir_p(body_path.dirname)
          File.write(body_path, JSON.pretty_generate(template) + "\n")
          body_template = body_path.relative_path_from(platform_dir).to_s
        end

        responses = operation.fetch("responses", {}).to_h do |status, raw_response|
          response = resolve(raw_response, source_path)
          content = response.is_a?(Hash) ? response.fetch("content", {}) : {}
          [status.to_s, content_summary(content)]
        end
        catalog["operations"] << {
          "group" => group,
          "command" => command_name,
          "operationId" => operation_id,
          "method" => method.upcase,
          "path" => path,
          "summary" => operation["summary"],
          "parameters" => params,
          "requestContent" => content_summary(body_content),
          "responseContent" => responses,
          "bodyTemplate" => body_template,
          "source" => Pathname(source_path).relative_path_from(platform_dir).to_s
        }
      end
    end
  end

  config = {"envs" => {"runtime" => {}}, "commands" => commands}
  FileUtils.mkdir_p(platform_dir.join(".hit"))
  File.write(platform_dir.join(".hit/config.json"), JSON.pretty_generate(config) + "\n")
  File.write(platform_dir.join("catalog.json"), JSON.pretty_generate(catalog) + "\n")
  puts "#{name}: #{catalog['operations'].length} operations, #{Dir[bodies_dir.join('**/*.json')].length} request bodies"
end

PLATFORMS.each { |name, settings| generate_platform(name, settings) }
