# yara-ffi

A Ruby library for using [YARA-X](https://virustotal.github.io/yara-x/) via FFI bindings. YARA-X is a modern, Rust-based implementation of YARA that's faster and safer than the original C implementation.

## Requirements

- Ruby 3.0 or later
- YARA-X C API library (`libyara_x_capi`) installed on your system

## Major Features

**🔍 Pattern Matching Analysis**: Extract detailed pattern match information with exact offsets, lengths, and matched data - perfect for forensic analysis.

**🛠️ Advanced Rule Compilation**: Use the `Yara::Compiler` class for complex scenarios with global variables, structured error reporting, and multiple rule sources.

**💾 Rule Serialization**: Compile rules once, serialize for persistence or transport, then deserialize for instant scanning - eliminating compilation overhead.

**🏷️ Metadata & Tags**: Full access to rule metadata with type safety and tag-based rule categorization and filtering.

**🌐 Global Variables**: Set string, boolean, integer, and float globals at runtime to customize rule behavior dynamically.

**📁 Namespace Support**: Organize rules logically, avoid naming conflicts, and access qualified rule names in large rule sets.

**⚡ Performance**: Configurable scan timeouts, efficient resource management with automatic cleanup, and parallel scanning support.

## Installation

Add this line to your application's Gemfile:

```ruby
gem "yara-ffi"
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install yara-ffi

## Quick Start

```ruby
require 'yara'

# Simple test
results = Yara.test(rule_string, data)
puts "Matched: #{results.first.rule_name}" if results.first&.match?

# Resource-managed scanning
Yara::Scanner.open(rule) do |scanner|
  scanner.compile
  results = scanner.scan(data)
end
```

**📖 For comprehensive usage examples, advanced features, and API documentation, see [USAGE.md](USAGE.md).**

## API Overview

**Core Classes**: `Yara`, `Yara::Scanner`, `Yara::Compiler`, `Yara::ScanResult`, `Yara::ScanResults`, `Yara::PatternMatch`

**Key Methods**: `Yara.test()`, `Yara.scan()`, `Scanner.open()`, `Scanner#scan()`, `ScanResult#pattern_matches`

**📖 For detailed API documentation, examples, and advanced usage patterns, see [USAGE.md](USAGE.md).**

## Installing YARA-X

You'll need the YARA-X C API library installed on your system. You can:

1. Build from source: https://github.com/VirusTotal/yara-x
2. Install via package manager (when available)
3. Use the provided Docker environment

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md) for detailed development setup instructions, testing guidelines, and contribution workflow.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/jonmagic/yara-ffi. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](CODE_OF_CONDUCT.md).

## License

The gem is available as open source under the terms of the [MIT License](LICENSE.txt).
