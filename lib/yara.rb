# frozen_string_literal: true

require "ffi"
require "pry"
require_relative "yara/ffi"
require_relative "yara/scan_result"
require_relative "yara/scanner"
require_relative "yara/version"

module Yara
  def self.start
    Yara::FFI.yr_initialize
  end

  def self.stop
    Yara::FFI.yr_finalize
  end

  def self.test(rule_string, test_string)
    start
    scanner = Yara::Scanner.new
    scanner.add_rule(rule_string)
    scanner.compile
    scanner.call(test_string)
  ensure
    scanner.close
    stop
  end
end
