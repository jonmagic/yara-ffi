# frozen_string_literal: true

require "ffi"
require "pry"
require_relative "yara/ffi"
require_relative "yara/scan_result"
require_relative "yara/scanner"
require_relative "yara/version"

module Yara
  def self.test(rule_string, test_string)
    scanner = Yara::Scanner.new
    scanner.add_rule(rule_string)
    scanner.compile
    scanner.call(test_string)
  ensure
    scanner.close if scanner
  end
end
