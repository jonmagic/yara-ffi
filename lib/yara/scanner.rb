module Yara
  class Scanner
    class NotCompiledError < StandardError; end

    ERROR_CALLBACK = proc do |error_level, file_name, line_number, rule, message, user_data|
      # noop
    end

    SCAN_FINISHED = 3

    # Public: Initializes instance of scanner. Under the hood this calls yr_initialize, then
    # creates a pointer, then calls yr_compiler_create with that pointer.
    #
    # error_callback: (optional) Proc to be called when an error occurs.
    # user_data: (optional) Instance of UserData to store and pass information.
    def initialize(error_callback: ERROR_CALLBACK, user_data: UserData.new)
      @error_callback = error_callback
      @user_data = user_data
      @compiler_pointer = ::FFI::MemoryPointer.new(:pointer)
      Yara::FFI.yr_compiler_create(@compiler_pointer)
      @compiler_pointer = @compiler_pointer.get_pointer(0)
      Yara::FFI.yr_compiler_set_callback(@compiler_pointer, error_callback, user_data)
    end

    # Public: Adds a rule to the scanner and returns the namespace value. If a namespace
    # is not provided it will default to nil and use the global namespace.
    #
    # rule_string - String containing the Yara rule to be added.
    # namespace:    (optional) String containing the namespace to be used for the rule.
    def add_rule(rule_string, namespace: nil)
      Yara::FFI.yr_compiler_add_string(@compiler_pointer, rule_string, namespace)
    end

    def compile
      @rules_pointer = ::FFI::MemoryPointer.new(:pointer)
      Yara::FFI.yr_compiler_get_rules(@compiler_pointer, @rules_pointer)
      @rules_pointer = @rules_pointer.get_pointer(0)
      Yara::FFI.yr_compiler_destroy(@compiler_pointer)
    end

    def call(test_string)
      raise NotCompiledError unless @rules_pointer

      results = []
      scanning = true
      result_callback = proc do |context_ptr, callback_type, rule, user_data|
        if callback_type == SCAN_FINISHED
          scanning = false
        else
          result = ScanResult.new(callback_type, rule, user_data)
          results << result if result.rule_outcome?
        end

        0 # ERROR_SUCCESS
      end

      test_string_bytesize = test_string.bytesize
      test_string_pointer = ::FFI::MemoryPointer.new(:char, test_string_bytesize)
      test_string_pointer.put_bytes(0, test_string)

      Yara::FFI.yr_rules_scan_mem(
        @rules_pointer,
        test_string_pointer,
        test_string_bytesize,
        0,
        result_callback,
        @user_data,
        1,
      )

      while scanning do
      end

      results
    end

    def close
      Yara::FFI.yr_rules_destroy(@rules_pointer)
    end
  end
end
