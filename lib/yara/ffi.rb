require_relative "yr_meta"
require_relative "yr_namespace"
require_relative "yr_string"
require_relative "yr_rule"
require_relative "user_data"

module Yara
  # FFI bindings to libyara.
  module FFI
    extend ::FFI::Library
    ffi_lib "libyara"

    # int yr_initialize(void)
    attach_function :yr_initialize, [], :int

    # int yr_finalize(void)
    attach_function :yr_finalize, [], :int

    # Creates a new compiler and assigns a pointer to that compiler
    # to the pointer passed into the method. To access the complier
    # get the pointer from the pointer you passed in.
    #
    # Usage:
    # > compiler_pointer = FFI::MemoryPointer.new(:pointer)
    # > Yara::FFI.yr_compiler_create(compiler_pointer)
    # > compiler_pointer = compiler_pointer.get_pointer(0)
    #
    # int yr_compiler_create(YR_COMPILER** compiler)
    attach_function :yr_compiler_create, [
      :pointer, # compiler_pointer*
    ], :int

    # int yr_compiler_destroy(YR_COMPILER* compiler)
    attach_function :yr_compiler_destroy, [
      :pointer, # compiler_pointer
    ], :void

    # void callback_function(
    #   int error_level,
    #   const char* file_name,
    #   int line_number,
    #   const YR_RULE* rule,
    #   const char* message,
    #   void* user_data)
    callback :add_rule_error_callback, [
      :int,       # error_level
      :string,    # file_name
      :int,       # line_number
      YrRule.by_ref, # YrRule*
      :string,    # message
      :pointer,   # user_data_pointer
    ], :void

    # void yr_compiler_set_callback(
    #   YR_COMPILER* compiler,
    #   YR_COMPILER_CALLBACK_FUNC callback,
    #   void* user_data)
    attach_function :yr_compiler_set_callback, [
      :pointer,                 # compiler_pointer*
      :add_rule_error_callback, # proc
      :pointer,                 # user_data_pointer
    ], :void

    # int yr_compiler_add_string(
    #   YR_COMPILER* compiler,
    #   const char* string,
    #   const char* namespace_)
    attach_function :yr_compiler_add_string, [
      :pointer,   # compiler_pointer*
      :string,    # rule string
      :string,    # namespace
    ], :int

    # int yr_compiler_get_rules(
    #   YR_COMPILER* compiler,
    #   YR_RULES** rules)
    attach_function :yr_compiler_get_rules, [
      :pointer, # compiler_pointer*
      :pointer, # rules_pointer*
    ], :int

    # int callback_function(
    #   int message,
    #   void* message_data,
    #   void* user_data)
    callback :scan_callback, [
      :pointer,       # YR_SCAN_CONTEXT*
      :int,           # message
      :pointer,       # message_data_pointer
      :pointer,       # user_data_pointer
    ], :int

    # int yr_rules_scan_mem(
    #   YR_RULES* rules,
    #   const uint8_t* buffer,
    #   size_t buffer_size,
    #   int flags,
    #   YR_CALLBACK_FUNC callback,
    #   void* user_data,
    #   int timeout)
    attach_function :yr_rules_scan_mem, [
      :pointer,       # rules_pointer*
      :string,        # buffer (aka test subject)
      :size_t,        # buffer size (String#bytesize)
      :int,           # flags
      :scan_callback, # proc
      :pointer,       # user_data_pointer
      :int,           # timeout in seconds
    ], :int
  end
end
