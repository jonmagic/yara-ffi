# yara-ffi AI Coding Instructions

This Ruby gem provides FFI bindings to YARA-X (Rust-based YARA implementation) for malware/pattern detection with advanced pattern matching analysis, rule compilation, serialization, and metadata support.

## Quick Development Guide

**Start Here for New Features:**
1. Run `script/test` (if Docker image missing, run `script/bootstrap` first)
2. Follow **Red-Green-Refactor** cycle with small semantic commits after each cycle
3. Scanner lifecycle: `add_rule()` → `compile()` → `scan()` → `close()`
4. Always use resource-safe patterns: `Scanner.open { |s| ... }` or manual `close()`
5. Interactive testing: `docker run -it --mount type=bind,src="$(pwd)",dst=/app yara-ffi bin/console`
6. **Documentation**: See `USAGE.md` for comprehensive examples and patterns

## Core Components (Read These Files First)

- `lib/yara/scanner.rb`: Main API - compile-then-scan workflow, resource management, global variables
- `lib/yara/compiler.rb`: Advanced rule compilation with globals, error diagnostics, serialization
- `lib/yara/scan_result.rb`: Enhanced result parsing with pattern matches, metadata, tags, namespaces
- `lib/yara/pattern_match.rb`: Detailed pattern match information with offsets and data extraction
- `lib/yara/ffi.rb`: Raw FFI bindings with error codes (`YRX_SUCCESS = 0`)
- Tests in `test/`: Comprehensive test coverage for all features
  - `test/scanner_test.rb`: Basic scanner patterns
  - `test/scanner_pattern_match_test.rb`: Pattern matching analysis
  - `test/compiler_test.rb`: Advanced compilation features
  - `test/serialize_test.rb`: Rule serialization/deserialization
  - `test/metadata_test.rb`: Metadata extraction
  - `test/tags_test.rb`: Tag support
  - `test/namespace_test.rb`: Namespace functionality

## Key Features & APIs

### Pattern Matching Analysis (NEW)
```ruby
# Detailed pattern match information
results = scanner.scan(data)
result = results.first

# Access specific pattern matches
matches = result.matches_for_pattern(:$suspicious)
matches.each do |match|
  puts "At offset #{match.offset}: #{match.matched_data(data)}"
end

# Pattern match convenience methods
result.pattern_matched?(:$api_call)  # => true/false
result.total_matches                 # => 5
result.all_matches                   # => [PatternMatch, ...]
```

### Advanced Rule Compilation (NEW)
```ruby
# Use Compiler for complex scenarios
compiler = Yara::Compiler.new
compiler.define_global_str("ENV", "production")
compiler.define_global_bool("DEBUG", false)
compiler.add_source(rule1, "rule1.yar")
compiler.add_source(rule2, "rule2.yar")

# Build and serialize
serialized = compiler.build_serialized
scanner = Yara::Scanner.from_serialized(serialized)
```

### Global Variables (NEW)
```ruby
# Set individual globals
scanner.set_global_str("ENV", "production")
scanner.set_global_int("MAX_SIZE", 1000)
scanner.set_global_bool("DEBUG", false)

# Bulk setting with error handling
scanner.set_globals({
  "ENV" => "production",
  "RETRIES" => 3
}, strict: false)
```

### Metadata & Tags (NEW)
```ruby
# Access metadata with type safety
result.rule_meta[:author]           # Raw access
result.metadata_string(:author)     # Type-safe String
result.metadata_int(:severity)      # Type-safe Integer

# Tag support
result.tags                         # => ["malware", "trojan"]
result.has_tag?("malware")         # => true
result.qualified_name               # => "namespace.rule_name"
```

## Critical FFI Patterns

**Memory Management (ALWAYS Required):**
```ruby
# Preferred - auto-cleanup
Scanner.open(rule_string) do |scanner|
  scanner.compile
  results = scanner.scan(data)
end

# Manual - MUST call close()
scanner = Scanner.new
# ... use scanner
scanner.close  # Memory leak without this!
```

**Error Handling - Check These First:**
```ruby
result = Yara::FFI.yrx_compile(@rule_source, @rules_pointer)
if result != Yara::FFI::YRX_SUCCESS
  error_msg = Yara::FFI.yrx_last_error
  raise CompilationError, "Failed: #{error_msg}"
end
```

**Library Loading Strategy (Multiple Fallbacks):**
```ruby
ffi_lib "/usr/local/lib/aarch64-linux-gnu/libyara_x_capi.so"  # Specific first
ffi_lib "yara_x_capi"  # System library fallback
```

## Development Environment

**Docker-First Development:** All development happens in Docker container with YARA-X pre-built:
- `script/test` - runs tests (builds image automatically if needed)
- `script/bootstrap` - only run if `script/test` fails due to missing Docker image
- Interactive: `docker run -it --mount type=bind,src="$(pwd)",dst=/app yara-ffi bin/console`

**TDD Workflow:** Follow Red-Green-Refactor with small semantic commits:
1. **Red**: Write failing test
2. **Green**: Make test pass with minimal code
3. **Refactor**: Clean up while keeping tests green
4. **Commit**: Small semantic commit describing the feature/fix

**Testing:** Uses Minitest. Tests in `test/` directory focus on Scanner lifecycle and rule matching.

## Common YARA Rule Patterns

**Basic Rule Template:**
```ruby
rule = <<-RULE
rule ExampleRule
{
  meta:
    description = "Example rule"
    author = "test"

  strings:
    $text = "pattern"
    $regex = /regex pattern/

  condition:
    $text or $regex
}
RULE
```

**Multiple Rules Pattern:**
```ruby
scanner = Scanner.new
scanner.add_rule(rule1)
scanner.add_rule(rule2)
scanner.compile
results = scanner.scan(data)  # Returns array of ScanResult objects
```

## Code Patterns

**Resource Management:**
```ruby
# Preferred block pattern
Scanner.open(rule_string) do |scanner|
  scanner.compile
  results = scanner.scan(data)
end  # Auto-cleanup

# Manual pattern - must call close()
scanner = Scanner.new
scanner.add_rule(rule)
scanner.compile
# ... use scanner
scanner.close  # Required!
```

**Error Handling:** Custom exceptions for different failure modes:
- `Scanner::CompilationError` - YARA rule syntax issues
- `Scanner::ScanError` - Runtime scanning failures
- `Scanner::NotCompiledError` - Scanning before compilation
- `Compiler::CompileError` - Compilation errors with structured diagnostics

**Enhanced Result Processing:** ScanResult now provides:
- Structured metadata access via YARA-X API
- Detailed pattern match information with offsets/lengths
- Tag extraction and querying
- Namespace support
- Pattern match convenience methods

## Performance & Advanced Features

**Rule Serialization for Production:**
```ruby
# Compile once, use many times
compiler = Yara::Compiler.new
compiler.add_source(ruleset)
serialized = compiler.build_serialized

# Create multiple scanners from same rules
scanners = 10.times.map { Yara::Scanner.from_serialized(serialized) }
```

**Timeout Configuration:**
```ruby
scanner.set_timeout(10000)  # 10 seconds
```

**Error Diagnostics:**
```ruby
begin
  compiler.build
rescue Yara::Compiler::CompileError
  errors = compiler.errors_json
  warnings = compiler.warnings_json
end
```

## Adding New FFI Functions

**Pattern to Follow:**
```ruby
# In lib/yara/ffi.rb
attach_function :yrx_new_function, [:param_types], :return_type

# In lib/yara/scanner.rb - always check return codes
result = Yara::FFI.yrx_new_function(params)
if result != Yara::FFI::YRX_SUCCESS
  error_msg = Yara::FFI.yrx_last_error
  raise ScanError, "Operation failed: #{error_msg}"
end
```

**Available FFI Functions (key ones):**
- `yrx_compile(src, rules_ptr)` - Compile rules from string
- `yrx_scanner_create(rules, scanner_ptr)` - Create scanner from compiled rules
- `yrx_scanner_scan(scanner, data, len)` - Scan data
- `yrx_scanner_set_global_*()` - Set global variables on scanner
- `yrx_scanner_set_timeout()` - Configure scan timeout
- `yrx_compiler_*()` - Advanced compilation functions
- `yrx_rules_serialize/deserialize()` - Rule serialization
- `yrx_rule_iter_*()` - Iterate rule components (patterns, metadata, tags)
- `yrx_pattern_iter_matches()` - Extract pattern match details
- `yrx_last_error()` - Get last error message
- Cleanup: `yrx_rules_destroy()`, `yrx_scanner_destroy()`, `yrx_compiler_destroy()`

## Documentation Structure

- `README.md`: Project overview, installation, minimal usage example
- `USAGE.md`: Comprehensive usage guide with quick reference + detailed examples
- `DEVELOPMENT.md`: Development setup and contribution workflow
- `.github/copilot-instructions.md`: This file - AI coding guidance

## Dependencies & Constraints

**Docker Dependencies:** Container includes Rust toolchain + cargo-c for building YARA-X from source.

When adding features, maintain the resource-managed Scanner pattern and ensure proper C memory cleanup.
