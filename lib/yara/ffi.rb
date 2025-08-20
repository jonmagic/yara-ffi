module Yara
  # Internal: Low-level FFI bindings to the YARA-X C API.
  #
  # This module provides direct Ruby FFI bindings to the yara_x_capi library.
  # It handles dynamic library loading with multiple fallback paths and exposes
  # the raw C functions for rule compilation, scanning, and resource management.
  #
  # The FFI module is primarily used internally by higher-level classes like
  # Scanner. Direct usage requires careful memory management and error handling.
  #
  # Examples
  #
  #   # Direct FFI usage (not recommended for normal use)
  #   rules_ptr = FFI::MemoryPointer.new(:pointer)
  #   result = Yara::FFI.yrx_compile("rule test { condition: true }", rules_ptr)
  #   raise "Error: #{Yara::FFI.yrx_last_error}" unless result == Yara::FFI::YRX_SUCCESS
  module FFI
    extend ::FFI::Library

    # Internal: Library search paths for yara_x_capi shared library.
    #
    # These paths are tried in order to locate the YARA-X C API library.
    # The first successful load is used. This supports various deployment
    # scenarios including system packages, Docker containers, and CI environments.
    library_paths = [
      "yara_x_capi",                                          # System library (preferred)
      "/usr/local/lib/x86_64-linux-gnu/libyara_x_capi.so",    # GitHub Actions/CI
      "/usr/local/lib/aarch64-linux-gnu/libyara_x_capi.so",   # Local Docker (ARM)
      "/usr/local/lib/libyara_x_capi.so",                     # Generic fallback
      "libyara_x_capi"                                        # Final fallback
    ]

    library_loaded = false
    library_paths.each do |path|
      begin
        ffi_lib path
        library_loaded = true
        break
      rescue LoadError
        next
      end
    end

    raise LoadError, "Could not load yara_x_capi library from any of: #{library_paths.join(', ')}" unless library_loaded

    # Public: Compile YARA rule source into executable rules object.
    #
    # This is the primary compilation function that parses YARA rule source code
    # and creates an optimized rules object for scanning. The rules object must
    # be freed with yrx_rules_destroy when no longer needed.
    #
    # src   - A String containing YARA rule source code
    # rules - A FFI::MemoryPointer that will receive the rules object pointer
    #
    # Examples
    #
    #   rules_ptr = FFI::MemoryPointer.new(:pointer)
    #   result = Yara::FFI.yrx_compile(rule_source, rules_ptr)
    #
    # Returns an Integer result code (YRX_SUCCESS on success).
    # C Signature: enum YRX_RESULT yrx_compile(const char *src, struct YRX_RULES **rules)
    attach_function :yrx_compile, [:string, :pointer], :int

    # Public: Get the last error message from YARA-X operations.
    #
    # When any YARA-X function returns an error code, this function provides
    # a human-readable description of what went wrong. The returned string
    # is managed by YARA-X and should not be freed.
    #
    # Examples
    #
    #   if result != YRX_SUCCESS
    #     error_msg = Yara::FFI.yrx_last_error
    #     raise "YARA Error: #{error_msg}"
    #   end
    #
    # Returns a String containing the last error message.
    # C Signature: const char* yrx_last_error(void)
    attach_function :yrx_last_error, [], :string

    # Public: Free memory associated with a compiled rules object.
    #
    # This function must be called to free the memory allocated by yrx_compile.
    # After calling this function, the rules pointer becomes invalid and should
    # not be used.
    #
    # rules - A Pointer to the rules object to destroy
    #
    # Examples
    #
    #   Yara::FFI.yrx_rules_destroy(rules_ptr)
    #
    # Returns nothing.
    # C Signature: void yrx_rules_destroy(struct YRX_RULES *rules)
    attach_function :yrx_rules_destroy, [:pointer], :void

    # Public: Create a scanner object from compiled rules.
    #
    # A scanner is needed to perform actual pattern matching against data.
    # Multiple scanners can be created from the same rules object to enable
    # concurrent scanning. The scanner must be freed with yrx_scanner_destroy.
    #
    # rules   - A Pointer to compiled rules object
    # scanner - A FFI::MemoryPointer that will receive the scanner object pointer
    #
    # Examples
    #
    #   scanner_ptr = FFI::MemoryPointer.new(:pointer)
    #   result = Yara::FFI.yrx_scanner_create(rules_ptr, scanner_ptr)
    #
    # Returns an Integer result code (YRX_SUCCESS on success).
    # C Signature: enum YRX_RESULT yrx_scanner_create(const struct YRX_RULES *rules, struct YRX_SCANNER **scanner)
    attach_function :yrx_scanner_create, [:pointer, :pointer], :int

    # Public: Free memory associated with a scanner object.
    #
    # This function must be called to free the memory allocated by
    # yrx_scanner_create. After calling this function, the scanner pointer
    # becomes invalid and should not be used.
    #
    # scanner - A Pointer to the scanner object to destroy
    #
    # Examples
    #
    #   Yara::FFI.yrx_scanner_destroy(scanner_ptr)
    #
    # Returns nothing.
    # C Signature: void yrx_scanner_destroy(struct YRX_SCANNER *scanner)
    attach_function :yrx_scanner_destroy, [:pointer], :void

    # Internal: Callback function type for rule matching events.
    #
    # This callback is invoked for each rule that matches during scanning.
    # The callback receives pointers to the matching rule and optional user data.
    #
    # rule      - A Pointer to the YRX_RULE structure
    # user_data - A Pointer to optional user-provided data
    #
    # C Signature: typedef void (*YRX_ON_MATCHING_RULE)(const struct YRX_RULE *rule, void *user_data)
    callback :matching_rule_callback, [:pointer, :pointer], :void

    # Public: Set callback for handling rule matches during scanning.
    #
    # This function registers a callback that will be invoked each time a rule
    # matches during scanning. The callback can extract information about the
    # matching rule and optionally halt scanning.
    #
    # scanner   - A Pointer to the scanner object
    # callback  - A Proc matching the matching_rule_callback signature
    # user_data - A Pointer to optional data passed to callback (can be nil)
    #
    # Examples
    #
    #   callback = proc { |rule_ptr, user_data| puts "Rule matched!" }
    #   result = Yara::FFI.yrx_scanner_on_matching_rule(scanner_ptr, callback, nil)
    #
    # Returns an Integer result code (YRX_SUCCESS on success).
    # C Signature: enum YRX_RESULT yrx_scanner_on_matching_rule(struct YRX_SCANNER *scanner, YRX_ON_MATCHING_RULE callback, void *user_data)
    attach_function :yrx_scanner_on_matching_rule, [:pointer, :matching_rule_callback, :pointer], :int

    # Public: Scan data using the configured scanner and rules.
    #
    # This function performs pattern matching against the provided data using
    # all rules in the scanner. Any matching rules trigger the registered
    # callback function. The data is scanned as binary regardless of content.
    #
    # scanner - A Pointer to the scanner object
    # data    - A Pointer to the data buffer to scan
    # len     - A size_t indicating the length of data in bytes
    #
    # Examples
    #
    #   data_ptr = FFI::MemoryPointer.new(:char, data.bytesize)
    #   data_ptr.put_bytes(0, data)
    #   result = Yara::FFI.yrx_scanner_scan(scanner_ptr, data_ptr, data.bytesize)
    #
    # Returns an Integer result code (YRX_SUCCESS on success).
    # C Signature: enum YRX_RESULT yrx_scanner_scan(struct YRX_SCANNER *scanner, const uint8_t *data, size_t len)
    attach_function :yrx_scanner_scan, [:pointer, :pointer, :size_t], :int

    # Public: Set timeout (in milliseconds) for a scanner.
    #
    # scanner - A Pointer to the scanner object
    # timeout - A uint64_t value representing timeout in milliseconds
    #
    # Returns an Integer result code (YRX_SUCCESS on success).
    # C Signature: enum YRX_RESULT yrx_scanner_set_timeout(struct YRX_SCANNER *scanner, uint64_t timeout)
    attach_function :yrx_scanner_set_timeout, [:pointer, :ulong_long], :int

    # Public: Extract the identifier (name) from a rule object.
    #
    # This function retrieves the rule name from a YRX_RULE pointer, typically
    # called from within a matching rule callback. The identifier is returned
    # as a pointer and length rather than a null-terminated string.
    #
    # rule  - A Pointer to the YRX_RULE structure
    # ident - A FFI::MemoryPointer that will receive the identifier pointer
    # len   - A FFI::MemoryPointer that will receive the identifier length
    #
    # Examples
    #
    #   ident_ptr = FFI::MemoryPointer.new(:pointer)
    #   len_ptr = FFI::MemoryPointer.new(:size_t)
    #   result = Yara::FFI.yrx_rule_identifier(rule_ptr, ident_ptr, len_ptr)
    #
    # Returns an Integer result code (YRX_SUCCESS on success).
    # C Signature: enum YRX_RESULT yrx_rule_identifier(const struct YRX_RULE *rule, const uint8_t **ident, size_t *len)
    attach_function :yrx_rule_identifier, [:pointer, :pointer, :pointer], :int

    # Internal: Callback function type for metadata iteration.
    #
    # This callback is invoked for each metadata entry during rule metadata
    # iteration. The callback receives pointers to the metadata and user data.
    #
    # metadata  - A Pointer to the YRX_METADATA structure
    # user_data - A Pointer to optional user-provided data
    #
    # C Signature: typedef void (*YRX_METADATA_CALLBACK)(const struct YRX_METADATA *metadata, void *user_data)
    callback :metadata_callback, [:pointer, :pointer], :void

    # Public: Iterate through all metadata entries in a rule.
    #
    # This function calls the provided callback for each metadata key-value pair
    # defined in the rule. Metadata includes information like author, description,
    # and custom tags defined in the rule's meta section.
    #
    # rule      - A Pointer to the YRX_RULE structure
    # callback  - A Proc matching the metadata_callback signature
    # user_data - A Pointer to optional data passed to callback (can be nil)
    #
    # Examples
    #
    #   callback = proc { |metadata_ptr, user_data| puts "Found metadata" }
    #   result = Yara::FFI.yrx_rule_iter_metadata(rule_ptr, callback, nil)
    #
    # Returns an Integer result code (YRX_SUCCESS on success).
    # C Signature: enum YRX_RESULT yrx_rule_iter_metadata(const struct YRX_RULE *rule, YRX_METADATA_CALLBACK callback, void *user_data)
    attach_function :yrx_rule_iter_metadata, [:pointer, :metadata_callback, :pointer], :int

    # Internal: Callback function type for pattern iteration.
    #
    # This callback is invoked for each pattern (string) during rule pattern
    # iteration. The callback receives pointers to the pattern and user data.
    #
    # pattern   - A Pointer to the YRX_PATTERN structure
    # user_data - A Pointer to optional user-provided data
    #
    # C Signature: typedef void (*YRX_PATTERN_CALLBACK)(const struct YRX_PATTERN *pattern, void *user_data)
    callback :pattern_callback, [:pointer, :pointer], :void

    # Public: Iterate through all patterns (strings) in a rule.
    #
    # This function calls the provided callback for each string pattern defined
    # in the rule. Patterns are the actual search terms that YARA looks for
    # during scanning, defined in the rule's strings section.
    #
    # rule      - A Pointer to the YRX_RULE structure
    # callback  - A Proc matching the pattern_callback signature
    # user_data - A Pointer to optional data passed to callback (can be nil)
    #
    # Examples
    #
    #   callback = proc { |pattern_ptr, user_data| puts "Found pattern" }
    #   result = Yara::FFI.yrx_rule_iter_patterns(rule_ptr, callback, nil)
    #
    # Returns an Integer result code (YRX_SUCCESS on success).
    # C Signature: enum YRX_RESULT yrx_rule_iter_patterns(const struct YRX_RULE *rule, YRX_PATTERN_CALLBACK callback, void *user_data)
    attach_function :yrx_rule_iter_patterns, [:pointer, :pattern_callback, :pointer], :int

    # Public: Extract the identifier (name) from a pattern object.
    #
    # This function retrieves the pattern identifier from a YRX_PATTERN pointer,
    # typically called from within a pattern iteration callback. Pattern
    # identifiers are the variable names like $string1, $hex_pattern, etc.
    #
    # pattern - A Pointer to the YRX_PATTERN structure
    # ident   - A FFI::MemoryPointer that will receive the identifier pointer
    # len     - A FFI::MemoryPointer that will receive the identifier length
    #
    # Examples
    #
    #   ident_ptr = FFI::MemoryPointer.new(:pointer)
    #   len_ptr = FFI::MemoryPointer.new(:size_t)
    #   result = Yara::FFI.yrx_pattern_identifier(pattern_ptr, ident_ptr, len_ptr)
    #
    # Returns an Integer result code (YRX_SUCCESS on success).
    # C Signature: enum YRX_RESULT yrx_pattern_identifier(const struct YRX_PATTERN *pattern, const uint8_t **ident, size_t *len)
    attach_function :yrx_pattern_identifier, [:pointer, :pointer, :pointer], :int

    # Public: YARA-X result codes for operation status.
    #
    # These constants represent the possible return values from YARA-X functions.
    # YRX_SUCCESS (0) indicates successful operation, while other values indicate
    # various error conditions that can be interpreted using yrx_last_error.

    # Public: Operation completed successfully.
    YRX_SUCCESS = 0

    # Public: YARA rule syntax error during compilation.
    YRX_SYNTAX_ERROR = 1

    # Public: Variable definition or reference error.
    YRX_VARIABLE_ERROR = 2

    # Public: Error during scanning operation.
    YRX_SCAN_ERROR = 3

    # Public: Scanning operation timed out.
    YRX_SCAN_TIMEOUT = 4

    # Public: Invalid argument passed to function.
    YRX_INVALID_ARGUMENT = 5
  end
end
