# frozen_string_literal: true

require "ffi"
require "pry"
require_relative "yara/version"
require_relative "yara/ffi"

# TBD
module Yara
  class Error < StandardError; end

  CALLBACK_MSG_RULE_MATCHING     = 1
  CALLBACK_MSG_RULE_NOT_MATCHING = 2
  CALLBACK_MSG_SCAN_FINISHED     = 3

  RULE_IDENTIFIER = 1

  def self.test(rule_string, test_string)
    user_data = UserData.new
    user_data[:number] = 42
    scanning = true
    results = []

    Yara::FFI.yr_initialize

    compiler_pointer = ::FFI::MemoryPointer.new(:pointer)
    Yara::FFI.yr_compiler_create(compiler_pointer)
    compiler_pointer = compiler_pointer.get_pointer(0)

    error_callback = proc do |error_level, file_name, line_number, rule, message, user_data|
      # noop
    end

    Yara::FFI.yr_compiler_set_callback(compiler_pointer, error_callback, user_data)
    Yara::FFI.yr_compiler_add_string(compiler_pointer, rule_string, nil)

    rules_pointer =::FFI::MemoryPointer.new(:pointer)
    Yara::FFI.yr_compiler_get_rules(compiler_pointer, rules_pointer)
    rules_pointer = rules_pointer.get_pointer(0)

    result_callback = proc do |context_ptr, message, message_data_ptr, user_data_ptr|
      rule = YrRule.new(message_data_ptr)

      case message
      when CALLBACK_MSG_RULE_MATCHING
        results << rule.values[RULE_IDENTIFIER]
      when CALLBACK_MSG_SCAN_FINISHED
        scanning = false
      end

      0 # ERROR_SUCCESS
    end

    Yara::FFI.yr_rules_scan_mem(
      rules_pointer,
      test_string,
      test_string.bytesize,
      0,
      result_callback,
      user_data,
      1,
    )

    while scanning do
    end

    results
  ensure
    Yara::FFI.yr_finalize
  end
end
