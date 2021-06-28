# frozen_string_literal: true

require "ffi"
require "pry"
require_relative "yara/version"
require_relative "yara/ffi"

# TBD
module Yara
  class Error < StandardError; end

  def self.test(rule_string, test_string)
    user_data_pointer = ::FFI::MemoryPointer.new(:pointer)
    result = nil

    Yara::FFI.yr_initialize

    compiler_pointer = ::FFI::MemoryPointer.new(:pointer)
    Yara::FFI.yr_compiler_create(compiler_pointer)
    compiler_pointer = compiler_pointer.get_pointer(0)

    Yara::FFI.yr_compiler_set_callback(compiler_pointer, Yara::FFI::ADD_RULE_ERROR_CALLBACK, user_data_pointer)
    Yara::FFI.yr_compiler_add_string(compiler_pointer, rule_string, nil)

    rules_pointer =::FFI::MemoryPointer.new(:pointer)
    Yara::FFI.yr_compiler_get_rules(compiler_pointer, rules_pointer)
    rules_pointer = rules_pointer.get_pointer(0)

    result_callback = proc do |message, message_data, user_data|
      puts message
      result = 0
    end

    Yara::FFI.yr_rules_scan_mem(
      rules_pointer,
      test_string,
      test_string.bytesize,
      0,
      result_callback,
      user_data_pointer,
      1,
    )

    while result.nil? do
      puts "waiting on result"
      sleep 0.1
    end

    result
  ensure
    Yara::FFI.yr_finalize
  end
end
