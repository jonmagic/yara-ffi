# frozen_string_literal: true

require "ffi"
require "pry"
require_relative "yara/ffi"
require_relative "yara/scan_result"
require_relative "yara/version"

module Yara
  SCAN_FINISHED = 3

  class Error < StandardError; end

  def self.test(rule_string, test_string)
    scanning = true
    results = []

    with_yara_setup(rule_string) do |compiler_pointer, rules_pointer, user_data|
      result_callback = proc do |context_ptr, callback_type, rule_ptr, user_data_ptr|
        if callback_type == SCAN_FINISHED
          scanning = false
        else
          result = ScanResult.new(callback_type, rule_ptr)
          results << result if result.rule_outcome?
        end

        0 # ERROR_SUCCESS
      end

      test_string_bytesize = test_string.bytesize
      test_string_pointer = ::FFI::MemoryPointer.new(:char, test_string_bytesize)
      test_string_pointer.put_bytes(0, test_string)

      Yara::FFI.yr_rules_scan_mem(
        rules_pointer,
        test_string_pointer,
        test_string_bytesize,
        0,
        result_callback,
        user_data,
        1,
      )

      while scanning do
      end
    end

    results
  ensure
    Yara::FFI.yr_rules_destroy(rules_pointer)
    Yara::FFI.yr_compiler_destroy(compiler_pointer)
    Yara::FFI.yr_finalize
  end

  def self.with_yara_setup(rule_string)
    Yara::FFI.yr_initialize

    ::FFI::MemoryPointer.new(:pointer) do |compiler_pointer|
      Yara::FFI.yr_compiler_create(compiler_pointer)
      compiler_pointer = compiler_pointer.get_pointer(0)

      user_data = UserData.new
      error_callback = proc do |error_level, file_name, line_number, rule, message, user_data|
        # noop
      end

      Yara::FFI.yr_compiler_set_callback(compiler_pointer, error_callback, user_data)
      Yara::FFI.yr_compiler_add_string(compiler_pointer, rule_string, nil)

      ::FFI::MemoryPointer.new(:pointer) do |rules_pointer|
        Yara::FFI.yr_compiler_get_rules(compiler_pointer, rules_pointer)
        rules_pointer = rules_pointer.get_pointer(0)

        yield(compiler_pointer, rules_pointer, user_data)
      end
    end
  end
end

