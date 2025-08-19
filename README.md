# yara-ffi

A Ruby library for using [YARA-X](https://virustotal.github.io/yara-x/) via FFI bindings. YARA-X is a modern, Rust-based implementation of YARA that's faster and safer than the original C implementation.

## Requirements

- Ruby 3.0 or later
- YARA-X C API library (`libyara_x_capi`) installed on your system

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

### Quick scanning with convenience methods

```ruby
rule = <<-RULE
rule ExampleRule
{
  meta:
    description = "Example rule for testing"

  strings:
    $text_string = "we were here"
    $text_regex = /were here/

  condition:
    $text_string or $text_regex
}
RULE

# Test a rule against data
results = Yara.test(rule, "one day we were here and then we were not")
puts results.first.match?  # => true
puts results.first.rule_name  # => "ExampleRule"

# Scan with a block for processing results
Yara.scan(rule, "sample data") do |result|
  puts "Matched: #{result.rule_name}"
end
```

### Manual scanner usage

```ruby
rule = <<-RULE
rule ExampleRule
{
  meta:
    string_meta = "an example rule for testing"
    int_meta = 42
    bool_meta = true

  strings:
    $my_text_string = "we were here"
    $my_text_regex = /were here/

  condition:
    $my_text_string or $my_text_regex
}
RULE

scanner = Yara::Scanner.new
scanner.add_rule(rule)
scanner.compile

results = scanner.scan("one day we were here and then we were not")
result = results.first

puts result.match?           # => true
puts result.rule_name        # => "ExampleRule"
puts result.rule_meta        # => {:string_meta=>"an example rule for testing", :int_meta=>42, :bool_meta=>true}
puts result.rule_strings     # => {:"$my_text_string"=>"we were here", :"$my_text_regex"=>"were here"}

scanner.close  # Clean up resources when done
```

### Block-based scanner usage

```ruby
# Automatically handles resource cleanup
Yara::Scanner.open(rule) do |scanner|
  scanner.compile
  results = scanner.scan("test data")
  # scanner is automatically closed when block exits
end
```

### Multiple rules

```ruby
rule1 = <<-RULE
rule RuleOne
{
  strings:
    $a = "pattern one"
  condition:
    $a
}
RULE

rule2 = <<-RULE
rule RuleTwo
{
  strings:
    $b = "pattern two"
  condition:
    $b
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

## API Reference

### Yara module methods

- `Yara.test(rule_string, data)` - Quick test of a rule against data, returns array of ScanResult objects
- `Yara.scan(rule_string, data, &block)` - Scan data with rule, optionally yielding each result to block

### Scanner class

- `Scanner.new` - Create a new scanner instance
- `Scanner.open(rule_string, namespace: nil, &block)` - Create scanner with optional rule and namespace, auto-cleanup with block
- `#add_rule(rule_string, namespace: nil)` - Add a YARA rule to the scanner
- `#compile` - Compile all added rules (required before scanning)
- `#scan(data, &block)` - Scan data and return ScanResults, or yield each result to block
- `#close` - Free scanner resources

### ScanResult class

- `#match?` - Returns true if rule matched
- `#rule_name` - Name of the matched rule
- `#rule_meta` - Hash of rule metadata (keys are symbols)
- `#rule_strings` - Hash of rule strings (keys are symbols with $ prefix)

## Installing YARA-X

You'll need the YARA-X C API library installed on your system. You can:

1. Build from source: https://github.com/VirusTotal/yara-x
2. Install via package manager (when available)
3. Use the provided Docker environment

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To run tests:
```bash
rake test
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/jonmagic/yara-ffi. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](https://github.com/jonmagic/yara-ffi/blob/main/CODE_OF_CONDUCT.md).

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the yara-ffi project's codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/jonmagic/yara-ffi/blob/main/CODE_OF_CONDUCT.md).
