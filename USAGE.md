# yara-ffi Usage Guide

This guide covers comprehensive usage of the yara-ffi Ruby gem, which provides FFI bindings to YARA-X (the modern Rust-based YARA implementation) for pattern matching and malware detection.

## Quick Reference

### Basic Scanning

```ruby
require 'yara'

# Quick test
results = Yara.test(rule_string, data)
puts "Matched: #{results.first.rule_name}" if results.first&.match?

# Scan with block
Yara.scan(rule_string, data) do |result|
  puts "Found: #{result.rule_name}"
end
```

### Scanner with Resource Management

```ruby
# Recommended: Automatic cleanup
Yara::Scanner.open(rule) do |scanner|
  scanner.compile
  results = scanner.scan(data)
end

# Manual: Must call close()
scanner = Yara::Scanner.new
scanner.add_rule(rule)
scanner.compile
results = scanner.scan(data)
scanner.close
```

### Pattern Match Analysis

```ruby
results = Yara.scan(rule, data)
result = results.first

# Check specific patterns
result.pattern_matched?(:$suspicious)      # => true/false
result.matches_for_pattern(:$api_call)     # => [PatternMatch, ...]
result.total_matches                       # => 5

# Get match details
matches = result.matches_for_pattern(:$pattern)
matches.each do |match|
  puts "At offset #{match.offset}: #{match.matched_data(data)}"
end
```

### Rule Metadata & Tags

```ruby
result = results.first

# Metadata access
result.rule_meta[:author]           # Raw access
result.metadata_string(:author)     # Type-safe access
result.metadata_int(:severity)      # Returns Integer or nil

# Tags
result.tags                         # => ["malware", "trojan"]
result.has_tag?("malware")         # => true
```

### Rule Iteration (Without Scanning)

```ruby
# Inspect compiled rules without scanning data
scanner.compile
scanner.each_rule do |rule|
  puts "Rule: #{rule.identifier}"
  puts "Namespace: #{rule.namespace}"
  puts "Tags: #{rule.tags.join(', ')}"

  # Access metadata
  rule.metadata.each { |k, v| puts "  #{k}: #{v}" }

  # Type-safe metadata access
  author = rule.metadata_string(:author)
  severity = rule.metadata_int(:severity)
end
```

### Global Variables

```ruby
# Set individual globals
scanner.set_global_str("ENV", "production")
scanner.set_global_bool("DEBUG", false)
scanner.set_global_int("MAX_SIZE", 1000)

# Set multiple globals
scanner.set_globals({
  "ENV" => "production",
  "DEBUG" => false,
  "RETRIES" => 3
})
```

### Rule Compilation & Serialization

```ruby
# Advanced compilation
compiler = Yara::Compiler.new
compiler.define_global_str("ENV", "prod")
compiler.add_source(rule1)
compiler.add_source(rule2)

# Serialize for reuse
serialized = compiler.build_serialized
File.binwrite("rules.bin", serialized)

# Later: deserialize and scan
data = File.binread("rules.bin")
scanner = Yara::Scanner.from_serialized(data)
results = scanner.scan(target_data)
```

### Error Handling

```ruby
begin
  Yara::Scanner.open(rule) do |scanner|
    scanner.compile
    scanner.set_timeout(5000)  # 5 seconds
    results = scanner.scan(data)
  end
rescue Yara::Scanner::CompilationError => e
  puts "Rule error: #{e.message}"
rescue Yara::Scanner::ScanError => e
  puts "Scan failed: #{e.message}"
end
```

### Performance Tips

```ruby
# 1. Use serialized rules for repeated scans
serialized = compiler.build_serialized
scanners = 10.times.map { Yara::Scanner.from_serialized(serialized) }

# 2. Set reasonable timeouts
scanner.set_timeout(10000)  # 10 seconds

# 3. Use block syntax for streaming
Yara.scan(rule, large_data) do |result|
  process_immediately(result)  # Don't accumulate all results
end
```

---

## Table of Contents

- [Quick Start](#quick-start)
- [Basic Scanning](#basic-scanning)
- [Advanced Scanner Usage](#advanced-scanner-usage)
- [Pattern Matching Analysis](#pattern-matching-analysis)
- [Rule Compilation & Management](#rule-compilation--management)
- [Global Variables](#global-variables)
- [Rule Serialization](#rule-serialization)
- [Metadata & Tags](#metadata--tags)
- [Namespaces](#namespaces)
- [Performance & Timeouts](#performance--timeouts)
- [Error Handling](#error-handling)
- [Best Practices](#best-practices)

## Quick Start

### Simple Rule Testing

```ruby
require 'yara'

# Basic rule
rule = <<-RULE
rule ExampleRule
{
  meta:
    description = "Example rule for testing"
    author = "security_team"

  strings:
    $text_string = "malware"
    $text_regex = /suspicious[0-9]+/

  condition:
    $text_string or $text_regex
}
RULE

# Test against data
results = Yara.test(rule, "This contains malware signatures")
puts results.first.match?       # => true
puts results.first.rule_name    # => "ExampleRule"
```

### Scanning with Block Processing

```ruby
# Process results as they're found
Yara.scan(rule, "sample data") do |result|
  puts "Matched: #{result.rule_name}"
  puts "  Author: #{result.rule_meta[:author]}"
  puts "  Total matches: #{result.total_matches}"
end
```

## Basic Scanning

### Using Convenience Methods

The `Yara.test` and `Yara.scan` methods provide the simplest interface for basic scanning:

```ruby
# Quick test - returns ScanResults collection
results = Yara.test(rule, data)
results.each { |result| puts "Match: #{result.rule_name}" }

# Scan with optional block processing
scan_results = Yara.scan(rule, data)
# or
Yara.scan(rule, data) { |result| process_match(result) }
```

### Multiple Rules

```ruby
rule1 = <<-RULE
rule RuleOne
{
  strings: $a = "pattern one"
  condition: $a
}
RULE

rule2 = <<-RULE
rule RuleTwo
{
  strings: $b = "pattern two"
  condition: $b
}
RULE

scanner = Yara::Scanner.new
scanner.add_rule(rule1)
scanner.add_rule(rule2)
scanner.compile

results = scanner.scan("text with pattern one and pattern two")
puts results.map(&:rule_name)  # => ["RuleOne", "RuleTwo"]
scanner.close
```

## Advanced Scanner Usage

### Resource Management

Always use proper resource management to avoid memory leaks:

```ruby
# Recommended: Automatic resource cleanup
Yara::Scanner.open(rule) do |scanner|
  scanner.compile
  results = scanner.scan(data)
  # scanner is automatically closed when block exits
end

# Manual resource management (requires explicit close)
scanner = Yara::Scanner.new
scanner.add_rule(rule)
scanner.compile
results = scanner.scan(data)
scanner.close  # Required to prevent memory leaks
```

### Scanner Lifecycle

The scanner follows a strict compile-then-scan workflow:

```ruby
scanner = Yara::Scanner.new

# 1. Add rules (can add multiple)
scanner.add_rule(rule1)
scanner.add_rule(rule2, namespace: "custom")

# 2. Compile all rules
scanner.compile

# 3. Scan data (can scan multiple times)
results1 = scanner.scan(data1)
results2 = scanner.scan(data2)

# 4. Clean up
scanner.close
```

### Iterating Rules Without Scanning

Extract rule information, metadata, and tags without scanning any data:

```ruby
# Setup: compile multiple rules
scanner = Yara::Scanner.new
scanner.add_rule(rule1)
scanner.add_rule(rule2, namespace: "malware")
scanner.compile

# Iterate through all compiled rules
scanner.each_rule do |rule|
  puts "Rule: #{rule.identifier}"
  puts "Namespace: #{rule.namespace || 'default'}"
  puts "Qualified Name: #{rule.qualified_name}"

  # Access metadata
  puts "\nMetadata:"
  rule.metadata.each do |key, value|
    puts "  #{key}: #{value}"
  end

  # Access tags
  if rule.tags.any?
    puts "\nTags: #{rule.tags.join(', ')}"
  end

  # Type-safe metadata access
  if author = rule.metadata_string(:author)
    puts "Author: #{author}"
  end

  if severity = rule.metadata_int(:severity)
    puts "Severity: #{severity}/10"
  end

  # Check for specific tags
  if rule.has_tag?("trojan")
    puts "⚠️  Trojan detection rule"
  end
end

# Use as an Enumerator
rules = scanner.each_rule.to_a
puts "Total rules: #{rules.size}"

# Filter rules by criteria
high_severity = scanner.each_rule.select do |rule|
  (rule.metadata_int(:severity) || 0) >= 8
end

malware_rules = scanner.each_rule.select do |rule|
  rule.has_tag?("malware")
end

scanner.close
```

**Example Rule with Metadata:**

```ruby
rule = <<-RULE
rule SuspiciousActivity : malware trojan
{
  meta:
    author = "Security Team"
    description = "Detects suspicious API calls"
    severity = 8
    date = "2024-01-15"
    is_active = true
    confidence = 0.95

  strings:
    $api1 = "VirtualAlloc"
    $api2 = "WriteProcessMemory"

  condition:
    all of them
}
RULE

scanner = Yara::Scanner.new
scanner.add_rule(rule, namespace: "detection")
scanner.compile

scanner.each_rule do |rule|
  puts "Rule: #{rule.identifier}"           # => "SuspiciousActivity"
  puts "Namespace: #{rule.namespace}"       # => "detection"
  puts "Full name: #{rule.qualified_name}"  # => "detection.SuspiciousActivity"

  # Access metadata with type safety
  puts "Author: #{rule.metadata_string(:author)}"           # => "Security Team"
  puts "Severity: #{rule.metadata_int(:severity)}"          # => 8
  puts "Active: #{rule.metadata_bool(:is_active)}"          # => true
  puts "Confidence: #{rule.metadata_float(:confidence)}"    # => 0.95

  # Check tags
  puts "Is malware rule: #{rule.has_tag?('malware')}"       # => true
  puts "Tags: #{rule.tags.join(', ')}"                      # => "malware, trojan"
end

scanner.close
```

**Use Case: Building a Rule Catalog**

```ruby
# Create a catalog of all rules without scanning
def build_rule_catalog(scanner)
  catalog = {}

  scanner.each_rule do |rule|
    catalog[rule.identifier] = {
      namespace: rule.namespace,
      description: rule.metadata_string(:description),
      author: rule.metadata_string(:author),
      severity: rule.metadata_int(:severity),
      tags: rule.tags,
      active: rule.metadata_bool(:is_active) != false
    }
  end

  catalog
end

scanner.compile
catalog = build_rule_catalog(scanner)

# Query the catalog
catalog.each do |name, info|
  puts "#{name}: #{info[:description]}" if info[:active]
end
```

## Pattern Matching Analysis

### Detailed Pattern Match Information

Access precise match locations and extracted data:

```ruby
rule = <<-RULE
rule PatternAnalysis
{
  strings:
    $api_call = "GetProcAddress"
    $registry = "HKEY_LOCAL_MACHINE"
    $suspicious = "cmd.exe"

  condition:
    2 of them
}
RULE

data = "Malware uses GetProcAddress and HKEY_LOCAL_MACHINE registry keys"
results = Yara.scan(rule, data)
result = results.first

# Access pattern matches by name
api_matches = result.matches_for_pattern(:$api_call)
api_matches.each do |match|
  puts "API call found at offset #{match.offset}"
  puts "Matched text: '#{match.matched_data(data)}'"
  puts "Match length: #{match.length} bytes"
end

# Get all pattern matches
result.pattern_matches.each do |pattern_name, matches|
  puts "Pattern #{pattern_name}: #{matches.size} matches"
  matches.each do |match|
    puts "  At offset #{match.offset}: '#{match.matched_data(data)}'"
  end
end
```

### Pattern Match Convenience Methods

```ruby
# Check if specific patterns matched
if result.pattern_matched?(:$suspicious)
  puts "Suspicious pattern detected!"
end

# Get total match count across all patterns
puts "Total matches: #{result.total_matches}"

# Get all matches sorted by location
all_matches = result.all_matches.sort_by(&:offset)
all_matches.each { |m| puts "Match at #{m.offset}" }

# Check for overlapping matches
match1 = result.matches_for_pattern(:$pattern1).first
match2 = result.matches_for_pattern(:$pattern2).first
if match1.overlaps?(match2)
  puts "Patterns overlap in the data"
end
```

## Rule Compilation & Management

### Using the Compiler Class

For advanced compilation scenarios, use `Yara::Compiler` directly:

```ruby
compiler = Yara::Compiler.new

# Add multiple sources
compiler.add_source(rule1, "rule1.yar")
compiler.add_source(rule2, "rule2.yar")

# Define global variables
compiler.define_global_str("ENV", "production")
compiler.define_global_int("MAX_SIZE", 1000)
compiler.define_global_bool("DEBUG", false)

# Build rules
rules_ptr = compiler.build

# Create scanner from compiled rules
scanner = Yara::Scanner.from_rules(rules_ptr, owns_rules: true)
results = scanner.scan(data)

# Cleanup
scanner.close
compiler.destroy
```

### Compilation Error Handling

```ruby
begin
  compiler.add_source("rule bad { condition: undefined_var }")
  compiler.build
rescue Yara::Compiler::CompileError => e
  # Get detailed error information
  errors = compiler.errors_json
  errors.each do |error|
    puts "Error: #{error['message']}"
    puts "Line: #{error['line']}"
  end

  # Get warnings too
  warnings = compiler.warnings_json
  warnings.each { |warn| puts "Warning: #{warn['message']}" }
end
```

## Global Variables

### Setting Global Variables on Scanner

```ruby
rule_with_globals = <<-RULE
rule ConfigurableRule
{
  condition:
    ENV == "production" and DEBUG == false and RETRIES >= 3
}
RULE

scanner = Yara::Scanner.new
scanner.add_rule(rule_with_globals)
scanner.compile

# Set individual globals
scanner.set_global_str("ENV", "production")
scanner.set_global_bool("DEBUG", false)
scanner.set_global_int("RETRIES", 5)
scanner.set_global_float("THRESHOLD", 0.95)

results = scanner.scan("")  # Rule depends only on globals
scanner.close
```

### Bulk Global Variable Setting

```ruby
# Set multiple globals at once
globals = {
  "ENV" => "production",
  "DEBUG" => false,
  "RETRIES" => 3,
  "THRESHOLD" => 0.95
}

# Strict mode (default) - raises on undefined globals
scanner.set_globals(globals)

# Lenient mode - silently skips undefined globals
scanner.set_globals(globals, strict: false)
```

## Rule Serialization

### Serialize and Deserialize Rules

Compile rules once and reuse them across processes or persistence:

```ruby
# Compile and serialize rules
compiler = Yara::Compiler.new
compiler.add_source(rule1)
compiler.add_source(rule2)
serialized_rules = compiler.build_serialized

# Save to file or database
File.binwrite("rules.bin", serialized_rules)

# Later, deserialize and use
serialized_data = File.binread("rules.bin")
scanner = Yara::Scanner.from_serialized(serialized_data)
results = scanner.scan(data)  # No compile step needed!

scanner.close
```

## Metadata & Tags

### Accessing Rule Metadata

```ruby
rule_with_metadata = <<-RULE
rule MetadataExample
{
  meta:
    author = "Security Team"
    description = "Detects malware patterns"
    version = 2
    severity = 8
    active = true
    confidence = 0.95

  strings:
    $pattern = "suspicious"

  condition:
    $pattern
}
RULE

results = Yara.scan(rule_with_metadata, "suspicious activity")
result = results.first

# Access metadata hash
puts result.rule_meta[:author]        # => "Security Team"
puts result.rule_meta[:severity]      # => 8
puts result.rule_meta[:active]        # => true

# Type-safe metadata access
puts result.metadata_string(:author)      # => "Security Team"
puts result.metadata_int(:severity)       # => 8
puts result.metadata_bool(:active)        # => true
puts result.metadata_float(:confidence)   # => 0.95
```

### Working with Tags

```ruby
rule_with_tags = <<-RULE
rule TaggedRule : malware suspicious windows
{
  meta:
    author = "Security Team"

  strings:
    $pattern = "evil"

  condition:
    $pattern
}
RULE

results = Yara.scan(rule_with_tags, "evil code")
result = results.first

# Access tags array
puts result.tags  # => ["malware", "suspicious", "windows"]

# Check for specific tags
if result.has_tag?("malware")
  puts "Malware detected!"
end

if result.has_tag?("windows") && result.has_tag?("suspicious")
  puts "Windows-specific suspicious activity"
end
```

## Namespaces

### Organizing Rules with Namespaces

```ruby
# Add rules to specific namespaces
scanner = Yara::Scanner.new
scanner.add_rule(malware_rule, namespace: "malware")
scanner.add_rule(pup_rule, namespace: "pup")
scanner.add_rule(generic_rule)  # Default namespace
scanner.compile

results = scanner.scan(data)
results.each do |result|
  puts "Match: #{result.qualified_name}"  # e.g., "malware.trojan_rule"
  puts "Namespace: #{result.namespace}"   # e.g., "malware"
end
scanner.close
```

### Namespace in Rule Source

```ruby
# Namespace can be defined in rule source
rule_with_namespace = <<-RULE
namespace malware {
  rule TrojanDetector
  {
    strings: $trojan = "trojan"
    condition: $trojan
  }
}
RULE

scanner.add_rule(rule_with_namespace)
```

## Performance & Timeouts

### Setting Scan Timeouts

```ruby
scanner = Yara::Scanner.new
scanner.add_rule(complex_rule)
scanner.compile

# Set timeout to 5 seconds (5000 milliseconds)
scanner.set_timeout(5000)

begin
  results = scanner.scan(large_data)
rescue Yara::Scanner::ScanError => e
  if e.message.include?("timeout")
    puts "Scan timed out - data too large or rule too complex"
  end
end

scanner.close
```

### Optimizing Performance

```ruby
# Use serialized rules for repeated usage
compiler = Yara::Compiler.new
compiler.add_source(ruleset)
serialized = compiler.build_serialized

# Create multiple scanners from same compiled rules
10.times do
  scanner = Yara::Scanner.from_serialized(serialized)
  # Process data in parallel
  Thread.new { scanner.scan(data_chunk) }
end
```

## Error Handling

### Common Exception Types

```ruby
begin
  scanner = Yara::Scanner.new
  scanner.add_rule(rule)
  scanner.compile
  results = scanner.scan(data)
rescue Yara::Scanner::CompilationError => e
  puts "Rule compilation failed: #{e.message}"
rescue Yara::Scanner::ScanError => e
  puts "Scanning failed: #{e.message}"
rescue Yara::Scanner::NotCompiledError => e
  puts "Attempted to scan before compiling: #{e.message}"
ensure
  scanner&.close
end
```

### Compiler Error Diagnostics

```ruby
begin
  compiler = Yara::Compiler.new
  compiler.add_source(invalid_rule)
  compiler.build
rescue Yara::Compiler::CompileError
  # Get structured error information
  errors = compiler.errors_json
  errors.each do |error|
    puts "Error at line #{error['line']}: #{error['message']}"
  end
ensure
  compiler&.destroy
end
```

## Best Practices

### 1. Resource Management

```ruby
# Always use block syntax for automatic cleanup
Yara::Scanner.open(rule) do |scanner|
  scanner.compile
  results = scanner.scan(data)
  # Automatic cleanup
end

# Or ensure manual cleanup
scanner = Yara::Scanner.new
begin
  # ... use scanner
ensure
  scanner.close
end
```

### 2. Efficient Rule Management

```ruby
# Compile rules once, use many times
compiler = Yara::Compiler.new
compiler.add_source(ruleset)
serialized = compiler.build_serialized

# Create scanners as needed
def create_scanner(rules_data)
  Yara::Scanner.from_serialized(rules_data)
end
```

### 3. Error-Resilient Scanning

```ruby
def safe_scan(rule, data)
  Yara::Scanner.open(rule) do |scanner|
    scanner.compile
    scanner.set_timeout(10000)  # 10 second timeout

    begin
      results = scanner.scan(data)
      return results
    rescue Yara::Scanner::ScanError => e
      puts "Scan failed: #{e.message}"
      return Yara::ScanResults.new  # Empty results
    end
  end
end
```

### 4. Pattern Analysis

```ruby
def analyze_matches(results, original_data)
  results.each do |result|
    puts "Rule: #{result.rule_name}"
    puts "Tags: #{result.tags.join(', ')}" if result.tags.any?

    result.pattern_matches.each do |pattern, matches|
      puts "  Pattern #{pattern}: #{matches.size} matches"
      matches.each do |match|
        context_start = [match.offset - 10, 0].max
        context_end = [match.end_offset + 10, original_data.length].min
        context = original_data[context_start...context_end]
        puts "    #{match.offset}: #{context.inspect}"
      end
    end
  end
end
```

### 5. Global Variable Management

```ruby
# Define globals at compile time for best performance
compiler = Yara::Compiler.new
compiler.define_global_str("ENV", ENV["RAILS_ENV"] || "development")
compiler.define_global_bool("DEBUG", Rails.env.development?)

# Or set globals per scan for dynamic behavior
scanner.set_globals({
  "CURRENT_TIME" => Time.now.to_i,
  "USER_LEVEL" => user.security_level
}, strict: false)
```

This comprehensive usage guide covers all major functionality available in yara-ffi. For development information, see [DEVELOPMENT.md](DEVELOPMENT.md).
