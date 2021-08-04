# frozen_string_literal: true

require "ffi"
require "pry"
require_relative "yara/version"
require_relative "yara/ffi"

# TBD
module Yara
  class Error < StandardError; end

  def self.test(rule_string, test_string)
    user_data = UserData.new
    user_data[:number] = 42
    result = nil

    Yara::FFI.yr_initialize

    compiler_pointer = ::FFI::MemoryPointer.new(:pointer)
    Yara::FFI.yr_compiler_create(compiler_pointer)
    compiler_pointer = compiler_pointer.get_pointer(0)

    error_callback = proc do |error_level, file_name, line_number, rule, message, user_data|
      puts error_level
      puts file_name
      puts line_number
      puts rule
      puts message
      puts user_data
    end

    Yara::FFI.yr_compiler_set_callback(compiler_pointer, error_callback, user_data)
    Yara::FFI.yr_compiler_add_string(compiler_pointer, rule_string, nil)

    rules_pointer =::FFI::MemoryPointer.new(:pointer)
    Yara::FFI.yr_compiler_get_rules(compiler_pointer, rules_pointer)
    rules_pointer = rules_pointer.get_pointer(0)

    result_callback = proc do |context_ptr, message_number, message_data_ptr, user_data_ptr|
      puts "message_number: #{message_number}"
      rule = YrRule.new(message_data_ptr)
      puts "members: #{rule.members}"
      binding.pry
      # puts rule.values.first.values.inspect
      # puts rule
      # puts rule.members.inspect
      # binding.pry

      # ud = UserData.new(user_data_ptr)
      # binding.pry
      # puts "user_data: #{user_data}"
      # puts user_data.members.inspect
      # puts user_data.values.inspect
      result = 0
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

    while result.nil? do
      puts "waiting on result"
      sleep 0.1
    end

    result
  ensure
    Yara::FFI.yr_finalize
  end
end
