# frozen_string_literal: true

require_relative "lib/yara/version"

Gem::Specification.new do |spec|
  spec.name = "yara-ffi"
  spec.version = Yara::VERSION
  spec.authors = ["Jonathan Hoyt"]
  spec.email = ["jonmagic@gmail.com"]

  spec.summary = "A Ruby API to libyara."
  spec.description = "Use libyara from Ruby via ffi bindings."
  spec.homepage = "https://github.com/jonmagic/yara-ffi"
  spec.license = "MIT"
  spec.required_ruby_version = Gem::Requirement.new(">= 2.4.0")

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/jonmagic/yara-ffi"
  spec.metadata["changelog_uri"] = "https://github.com/jonmagic/yara-ffi/main/CHANGELOG.md,"

  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{\A(?:test|spec|features)/}) }
  end
  spec.require_paths = ["lib"]
end
