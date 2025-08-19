# frozen_string_literal: true

require_relative "lib/yara/version"

Gem::Specification.new do |spec|
  spec.name = "yara-ffi"
  spec.version = Yara::VERSION
  spec.authors = ["Jonathan Hoyt"]
  spec.email = ["jonmagic@gmail.com"]

  spec.summary = "A Ruby API to YARA-X."
  spec.description = "Use YARA-X from Ruby via FFI bindings."
  spec.homepage = "https://github.com/jonmagic/yara-ffi"
  spec.license = "MIT"
  spec.required_ruby_version = Gem::Requirement.new(">= 3.2.0")

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/jonmagic/yara-ffi"
  spec.metadata["changelog_uri"] = "https://github.com/jonmagic/yara-ffi/main/CHANGELOG.md,"

  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{\A(?:test|spec|features)/}) }
  end
  spec.require_paths = ["lib"]
  spec.add_dependency "ffi"
end
