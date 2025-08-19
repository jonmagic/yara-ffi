# yara-ffi AI Coding Instructions

This Ruby gem provides FFI bindings to YARA-X (Rust-based YARA implementation) for malware/pattern detection.

## Quick Development Guide

**Start Here for New Features:**
1. Run `script/test` (if Docker image missing, run `script/bootstrap` first)
2. Follow **Red-Green-Refactor** cycle with small semantic commits after each cycle
3. Scanner lifecycle: `add_rule()` → `compile()` → `scan()` → `close()`
4. Always use resource-safe patterns: `Scanner.open { |s| ... }` or manual `close()`
5. Interactive testing: `docker run -it --mount type=bind,src="$(pwd)",dst=/app yara-ffi bin/console`

## Core Components (Read These Files First)

- `lib/yara/scanner.rb`: Main API - compile-then-scan workflow, resource management
- `lib/yara/ffi.rb`: Raw FFI bindings with error codes (`YRX_SUCCESS = 0`)
- `lib/yara/scan_result.rb`: Result parsing (temporary regex-based metadata extraction)
- Tests in `test/scanner_test.rb`: Working examples of all patterns

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
- `CompilationError` - YARA rule syntax issues
- `ScanError` - Runtime scanning failures
- `NotCompiledError` - Scanning before compilation

**Metadata Parsing:** ScanResult parses YARA rule metadata and strings via regex from rule source (temporary solution until YARA-X API improvements).

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
- `yrx_last_error()` - Get last error message
- Cleanup: `yrx_rules_destroy()`, `yrx_scanner_destroy()`

## Dependencies & Constraints

**Docker Dependencies:** Container includes Rust toolchain + cargo-c for building YARA-X from source.

When adding features, maintain the resource-managed Scanner pattern and ensure proper C memory cleanup.
