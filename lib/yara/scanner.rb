module Yara
  # Public: High-level interface for compiling YARA rules and scanning data.
  #
  # The Scanner class provides a Ruby-friendly interface to YARA-X functionality.
  # It manages the complete lifecycle of rule compilation, scanner creation, data
  # scanning, and proper resource cleanup. Use this class for all normal YARA
  # operations rather than the low-level FFI bindings.
  #
  # The scanner follows a compile-then-scan workflow:
  # 1. Create scanner and add rules with add_rule()
  # 2. Compile rules with compile()
  # 3. Scan data with scan()
  # 4. Clean up resources with close() or use block syntax for automatic cleanup
  #
  # Examples
  #
  #   # Automatic resource management (recommended)
  #   rule = 'rule test { strings: $a = "hello" condition: $a }'
  #   Scanner.open(rule) do |scanner|
  #     scanner.compile
  #     results = scanner.scan("hello world")
  #   end
  #
  #   # Manual resource management
  #   scanner = Scanner.new
  #   scanner.add_rule(rule)
  #   scanner.compile
  #   results = scanner.scan(data)
  #   scanner.close  # Required to prevent memory leaks
  class Scanner
    # Public: Raised when YARA rule compilation fails.
    #
    # This exception indicates syntax errors, undefined variables, or other
    # issues that prevent successful rule compilation. The message includes
    # details from YARA-X about what went wrong.
    class CompilationError < StandardError; end

    # Public: Raised when scanning operations fail.
    #
    # This exception indicates runtime errors during data scanning, such as
    # I/O errors, memory issues, or internal YARA-X failures.
    class ScanError < StandardError; end

    # Public: Raised when attempting to scan before compiling rules.
    #
    # This exception indicates a programming error where scan() was called
    # before compile(). Rules must be compiled before scanning can occur.
    class NotCompiledError < StandardError; end

    # Public: Initialize a new Scanner instance.
    #
    # Creates a new scanner in an empty state. Rules must be added with
    # add_rule() and compiled with compile() before scanning can occur.
    #
    # Examples
    #
    #   scanner = Scanner.new
    #   scanner.add_rule('rule test { condition: true }')
    #   scanner.compile
    def initialize
      @rules_pointer = nil
      @scanner_pointer = nil
      @rule_source = ""
    end

    # Public: Add a YARA rule to the scanner for later compilation.
    #
    # Rules are accumulated as source code and compiled together when compile()
    # is called. Multiple rules can be added to create rule sets. Optional
    # namespacing allows logical grouping of related rules.
    #
    # rule_string - A String containing a complete YARA rule definition
    # namespace   - An optional String namespace to contain the rule
    #
    # Examples
    #
    #   scanner.add_rule('rule test1 { condition: true }')
    #   scanner.add_rule('rule test2 { condition: false }', namespace: 'testing')
    #
    # Returns nothing.
    def add_rule(rule_string, namespace: nil)
      # For now, we'll just store the rule source and compile later
      # yara-x doesn't have separate add_rule like libyara
      if namespace
        @rule_source += "\nnamespace #{namespace} {\n#{rule_string}\n}\n"
      else
        @rule_source += "\n#{rule_string}\n"
      end
    end

    # Public: Compile all added rules into an executable scanner.
    #
    # This method compiles all rules added via add_rule() into an optimized
    # form suitable for scanning. Compilation must succeed before any scanning
    # operations can be performed. The compiled rules are used to create an
    # internal scanner object for efficient data processing.
    #
    # Examples
    #
    #   scanner = Scanner.new
    #   scanner.add_rule('rule test { condition: true }')
    #   scanner.compile
    #
    # Returns nothing.
    # Raises CompilationError if rule compilation fails.
    def compile
      raise CompilationError, "No rules added" if @rule_source.empty?

      @rules_pointer = ::FFI::MemoryPointer.new(:pointer)
      result = Yara::FFI.yrx_compile(@rule_source, @rules_pointer)

      if result != Yara::FFI::YRX_SUCCESS
        error_msg = Yara::FFI.yrx_last_error
        raise CompilationError, "Failed to compile rules: #{error_msg}"
      end

      @rules_pointer = @rules_pointer.get_pointer(0)

      # Create scanner
      @scanner_pointer_holder = ::FFI::MemoryPointer.new(:pointer)
      result = Yara::FFI.yrx_scanner_create(@rules_pointer, @scanner_pointer_holder)

      if result != Yara::FFI::YRX_SUCCESS
        error_msg = Yara::FFI.yrx_last_error
        raise CompilationError, "Failed to create scanner: #{error_msg}"
      end

      @scanner_pointer = @scanner_pointer_holder.get_pointer(0)
    end

    # Public: Scan data against compiled rules.
    #
    # This method scans the provided data using all compiled rules, returning
    # information about any matches found. When a block is provided, each
    # matching rule is yielded immediately as it's discovered during scanning.
    #
    # Scanning treats the input as binary data regardless of content type.
    # String encoding is preserved but pattern matching occurs at the byte level.
    #
    # test_string - A String containing the data to scan
    # block       - Optional block that receives each ScanResult as found
    #
    # Examples
    #
    #   # Collect all results
    #   results = scanner.scan("data to scan")
    #   results.each { |match| puts match.rule_name }
    #
    #   # Process matches immediately
    #   scanner.scan("data to scan") do |match|
    #     puts "Found: #{match.rule_name}"
    #   end
    #
    # Returns a ScanResults object containing matches when no block given.
    # Returns nil when a block is provided (matches are yielded instead).
    # Raises NotCompiledError if compile() has not been called.
    # Raises ScanError if scanning fails.
    def scan(test_string)
      raise NotCompiledError, "Rules not compiled. Call compile() first." unless @scanner_pointer

      results = ScanResults.new

      # Set up callback for matching rules
      callback = proc do |rule_ptr, user_data|
        # Extract rule identifier
        ident_ptr = ::FFI::MemoryPointer.new(:pointer)
        len_ptr = ::FFI::MemoryPointer.new(:size_t)

        if Yara::FFI.yrx_rule_identifier(rule_ptr, ident_ptr, len_ptr) == Yara::FFI::YRX_SUCCESS
          identifier_ptr = ident_ptr.get_pointer(0)
          identifier_len = len_ptr.get_ulong(0)
          rule_name = identifier_ptr.read_string(identifier_len)

          # Create a result with the rule source for metadata/string parsing
          result = ScanResult.new(rule_name, rule_ptr, true, @rule_source)
          results << result

          yield result if block_given?
        end
      end

      # Set the callback
      result = Yara::FFI.yrx_scanner_on_matching_rule(@scanner_pointer, callback, nil)
      if result != Yara::FFI::YRX_SUCCESS
        error_msg = Yara::FFI.yrx_last_error
        raise ScanError, "Failed to set callback: #{error_msg}"
      end

      # Scan the data
      test_string_bytesize = test_string.bytesize
      test_string_pointer = ::FFI::MemoryPointer.new(:char, test_string_bytesize)
      test_string_pointer.put_bytes(0, test_string)

      result = Yara::FFI.yrx_scanner_scan(@scanner_pointer, test_string_pointer, test_string_bytesize)
      if result != Yara::FFI::YRX_SUCCESS
        error_msg = Yara::FFI.yrx_last_error
        raise ScanError, "Scan failed: #{error_msg}"
      end

      block_given? ? nil : results
    end

    # Public: Set a timeout for scanning operations on this scanner (milliseconds).
    #
    # This method configures the scanner to abort scans that take longer than
    # the given timeout value. The timeout is specified in milliseconds.
    #
    # timeout_ms - Integer milliseconds to use as timeout
    #
    # Returns nothing. Raises ScanError on failure to set the timeout.
    def set_timeout(timeout_ms)
      raise NotCompiledError, "Scanner not initialized" unless @scanner_pointer

      result = Yara::FFI.yrx_scanner_set_timeout(@scanner_pointer, timeout_ms)
      if result != Yara::FFI::YRX_SUCCESS
        error_msg = Yara::FFI.yrx_last_error
        raise ScanError, "Failed to set timeout: #{error_msg}"
      end
      nil
    end

    # Public: Free all resources associated with this scanner.
    #
    # This method releases memory allocated by YARA-X for the compiled rules
    # and scanner objects. It must be called to prevent memory leaks when
    # using manual resource management. After calling close(), the scanner
    # cannot be used for further operations.
    #
    # The open() class method with a block automatically calls close() to
    # ensure proper cleanup even if exceptions occur.
    #
    # Examples
    #
    #   scanner = Scanner.new
    #   # ... use scanner
    #   scanner.close  # Required for cleanup
    #
    # Returns nothing.
    def close
      Yara::FFI.yrx_scanner_destroy(@scanner_pointer) if @scanner_pointer
      Yara::FFI.yrx_rules_destroy(@rules_pointer) if @rules_pointer
      @scanner_pointer = nil
      @rules_pointer = nil
    end

    # Public: Create a scanner with automatic resource management.
    #
    # This class method creates a Scanner instance and optionally adds an
    # initial rule. When used with a block, it ensures proper resource cleanup
    # by automatically calling close() even if exceptions occur during scanning.
    # This is the recommended way to use Scanner for most applications.
    #
    # rule_string - An optional String containing a YARA rule definition
    # namespace   - An optional String namespace for the initial rule
    # block       - Block that receives the scanner instance
    #
    # Examples
    #
    #   # Block syntax with automatic cleanup (recommended)
    #   Scanner.open(rule) do |scanner|
    #     scanner.compile
    #     results = scanner.scan(data)
    #   end
    #
    #   # Without block (manual cleanup required)
    #   scanner = Scanner.open(rule)
    #   scanner.compile
    #   # ... use scanner
    #   scanner.close
    #
    # Returns the result of the block when block given.
    # Returns a new Scanner instance when no block given.
    def self.open(rule_string = nil, namespace: nil)
      scanner = new
      scanner.add_rule(rule_string, namespace: namespace) if rule_string

      if block_given?
        begin
          yield scanner
        ensure
          scanner.close
        end
      else
        scanner
      end
    end
  end
end
