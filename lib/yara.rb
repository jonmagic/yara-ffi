# frozen_string_literal: true

require "ffi"
require "pry"
require_relative "yara/ffi"
require_relative "yara/scan_result"
require_relative "yara/scan_results"
require_relative "yara/scanner"
require_relative "yara/version"

module Yara
  def self.test(rule_string, test_string)
    Scanner.open(rule_string) do |scanner|
      scanner.compile
      scanner.scan(test_string)
    end
  end

  def self.scan(rule_string, data, &block)
    Scanner.open(rule_string) do |scanner|
      scanner.compile
      scanner.scan(data, &block)
    end
  end
end
