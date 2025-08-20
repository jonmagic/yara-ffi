# frozen_string_literal: true

require "ffi"
require "pry"
require_relative "yara/ffi"
require_relative "yara/scan_result"
require_relative "yara/scan_results"
require_relative "yara/scanner"
require_relative "yara/compiler"
require_relative "yara/version"

# Public: Main module providing Ruby FFI bindings to YARA-X for pattern
# matching and malware detection.
#
# This gem provides a Ruby interface to the YARA-X library (Rust-based YARA
# implementation) for scanning files, strings, and binary data using YARA rules.
# It offers both high-level convenience methods and low-level scanner control.
#
# Examples
#
#   # Quick scanning with automatic resource cleanup
#   rule = 'rule test { strings: $a = "hello" condition: $a }'
#   results = Yara.scan(rule, "hello world")
#
#   # Manual scanner control for advanced use cases
#   Yara::Scanner.open(rule) do |scanner|
#     scanner.compile
#     results = scanner.scan(data)
#   end
module Yara
  # Public: Test a YARA rule against data with automatic cleanup.
  #
  # This is a convenience method that handles the complete scan lifecycle:
  # rule compilation, scanning, and resource cleanup. Use this for simple
  # one-off scans where you don't need fine-grained control.
  #
  # rule_string - A String containing the YARA rule definition
  # test_string - A String containing the data to scan
  #
  # Examples
  #
  #   rule = 'rule test { strings: $a = "malware" condition: $a }'
  #   results = Yara.test(rule, "potential malware signature")
  #   # => #<Yara::ScanResults:0x... @results=[...]>
  #
  # Returns a Yara::ScanResults object containing any matching rules.
  # Raises Yara::Scanner::CompilationError if the rule is invalid.
  # Raises Yara::Scanner::ScanError if scanning fails.
  def self.test(rule_string, test_string)
    Scanner.open(rule_string) do |scanner|
      scanner.compile
      scanner.scan(test_string)
    end
  end

  # Public: Scan data with a YARA rule, optionally yielding each match.
  #
  # This is a convenience method for scanning with optional block-based
  # processing of results. When a block is provided, each matching rule
  # is yielded as it's found during scanning.
  #
  # rule_string - A String containing the YARA rule definition
  # data        - A String containing the data to scan
  # block       - Optional block that receives each ScanResult as found
  #
  # Examples
  #
  #   # Collect all results
  #   results = Yara.scan(rule, data)
  #
  #   # Process matches as they're found
  #   Yara.scan(rule, data) do |match|
  #     puts "Found: #{match.rule_name}"
  #   end
  #
  # Returns a Yara::ScanResults object when no block given, nil when block given.
  # Raises Yara::Scanner::CompilationError if the rule is invalid.
  # Raises Yara::Scanner::ScanError if scanning fails.
  def self.scan(rule_string, data, &block)
    Scanner.open(rule_string) do |scanner|
      scanner.compile
      scanner.scan(data, &block)
    end
  end
end
