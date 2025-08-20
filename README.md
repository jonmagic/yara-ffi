# yara-ffi

A Ruby library for using [YARA-X](https://virustotal.github.io/yara-x/) via FFI bindings. YARA-X is a modern, Rust-based implementation of YARA that's faster and safer than the original C implementation.

## Requirements

- Ruby 3.0 or later
- YARA-X C API library (`libyara_x_capi`) installed on your system

## What's New

Since version 4.0.0, yara-ffi has been significantly enhanced with advanced YARA-X features:

### 🔍 **Pattern Matching Analysis** (NEW)
- Detailed pattern match information with exact offsets and lengths
- Extract matched data from specific locations
- Analyze overlapping and repeated pattern matches
- Perfect for forensic analysis and data extraction

### 🛠️ **Advanced Rule Compilation** (NEW)
- `Yara::Compiler` class for complex compilation scenarios
- Global variable definition at compile time
- Structured error and warning reporting via JSON
- Support for multiple rule sources with origin tracking

### 💾 **Rule Serialization** (NEW)
- Compile rules once, serialize for persistence or transport
- Deserialize pre-compiled rules for instant scanning
- Eliminate repeated compilation overhead in production

### 🏷️ **Metadata & Tags Support** (NEW)
- Full access to rule metadata with proper type handling
- Tag-based rule categorization and filtering
- Type-safe metadata access methods

### 🌐 **Global Variables** (NEW)
- Set string, boolean, integer, and float globals
- Bulk global variable setting with error handling modes
- Runtime rule behavior customization

### 📁 **Namespace Support** (NEW)
- Organize rules into logical namespaces
- Avoid naming conflicts in large rule sets
- Qualified rule name access

### ⚡ **Performance Enhancements** (NEW)
- Configurable scan timeouts to prevent runaway scans
- Efficient resource management with automatic cleanup
- Parallel scanning support with serialized rules

## Installation

Add this line to your application's Gemfile:

```ruby
gem "yara-ffi"
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install yara-ffi

## Usage

```ruby
require 'yara'

# Quick test
results = Yara.test(rule_string, data)
puts "Matched: #{results.first.rule_name}" if results.first&.match?

# Resource-managed scanning
Yara::Scanner.open(rule) do |scanner|
  scanner.compile
  results = scanner.scan(data)
end
```

**For complete usage examples and API documentation, see [USAGE.md](USAGE.md).**

## Key Features

This gem provides comprehensive YARA-X functionality including:

- **Pattern Matching Analysis**: Detailed pattern match information with exact offsets and lengths
- **Rule Compilation & Management**: Advanced compilation with global variables and error diagnostics
- **Rule Serialization**: Compile once, use many times across processes
- **Metadata & Tags**: Full access to rule metadata and tag-based categorization
- **Namespaces**: Organize rules logically and avoid naming conflicts
- **Global Variables**: Dynamic rule behavior with runtime variable setting
- **Performance Optimization**: Timeouts, efficient resource usage, and parallel scanning

## API Reference

**Core Classes**: `Yara`, `Yara::Scanner`, `Yara::Compiler`, `Yara::ScanResult`, `Yara::ScanResults`, `Yara::PatternMatch`

**Key Methods**: `Yara.test()`, `Yara.scan()`, `Scanner.open()`, `Scanner#scan()`, `ScanResult#pattern_matches`

For detailed API documentation and examples, see **[USAGE.md](USAGE.md)**.

## Installing YARA-X

You'll need the YARA-X C API library installed on your system. You can:

1. Build from source: https://github.com/VirusTotal/yara-x
2. Install via package manager (when available)
3. Use the provided Docker environment

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md) for detailed development setup instructions, testing guidelines, and contribution workflow.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/jonmagic/yara-ffi. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](https://github.com/jonmagic/yara-ffi/blob/main/CODE_OF_CONDUCT.md).

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the yara-ffi project's codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/jonmagic/yara-ffi/blob/main/CODE_OF_CONDUCT.md).
