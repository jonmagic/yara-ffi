module Yara
  # FFI bindings to yara-x C API.
  module FFI
    extend ::FFI::Library

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

    # Simple compilation function for basic use cases
    # enum YRX_RESULT yrx_compile(const char *src, struct YRX_RULES **rules)
    attach_function :yrx_compile, [:string, :pointer], :int

    # const char* yrx_last_error(void)
    attach_function :yrx_last_error, [], :string

    # void yrx_rules_destroy(struct YRX_RULES *rules)
    attach_function :yrx_rules_destroy, [:pointer], :void

    # enum YRX_RESULT yrx_scanner_create(const struct YRX_RULES *rules, struct YRX_SCANNER **scanner)
    attach_function :yrx_scanner_create, [:pointer, :pointer], :int

    # void yrx_scanner_destroy(struct YRX_SCANNER *scanner)
    attach_function :yrx_scanner_destroy, [:pointer], :void

    # Callback for matching rules
    # typedef void (*YRX_ON_MATCHING_RULE)(const struct YRX_RULE *rule, void *user_data)
    callback :matching_rule_callback, [:pointer, :pointer], :void

    # enum YRX_RESULT yrx_scanner_on_matching_rule(struct YRX_SCANNER *scanner, YRX_ON_MATCHING_RULE callback, void *user_data)
    attach_function :yrx_scanner_on_matching_rule, [:pointer, :matching_rule_callback, :pointer], :int

    # enum YRX_RESULT yrx_scanner_scan(struct YRX_SCANNER *scanner, const uint8_t *data, size_t len)
    attach_function :yrx_scanner_scan, [:pointer, :pointer, :size_t], :int

    # Rule information functions
    # enum YRX_RESULT yrx_rule_identifier(const struct YRX_RULE *rule, const uint8_t **ident, size_t *len)
    attach_function :yrx_rule_identifier, [:pointer, :pointer, :pointer], :int

    # Metadata iteration
    # enum YRX_RESULT yrx_rule_iter_metadata(const struct YRX_RULE *rule, YRX_METADATA_CALLBACK callback, void *user_data)
    callback :metadata_callback, [:pointer, :pointer], :void
    attach_function :yrx_rule_iter_metadata, [:pointer, :metadata_callback, :pointer], :int

    # Pattern iteration
    # enum YRX_RESULT yrx_rule_iter_patterns(const struct YRX_RULE *rule, YRX_PATTERN_CALLBACK callback, void *user_data)
    callback :pattern_callback, [:pointer, :pointer], :void
    attach_function :yrx_rule_iter_patterns, [:pointer, :pattern_callback, :pointer], :int

    # Pattern information
    # enum YRX_RESULT yrx_pattern_identifier(const struct YRX_PATTERN *pattern, const uint8_t **ident, size_t *len)
    attach_function :yrx_pattern_identifier, [:pointer, :pointer, :pointer], :int

    # Result codes
    YRX_SUCCESS = 0
    YRX_SYNTAX_ERROR = 1
    YRX_VARIABLE_ERROR = 2
    YRX_SCAN_ERROR = 3
    YRX_SCAN_TIMEOUT = 4
    YRX_INVALID_ARGUMENT = 5
  end
end
