# yara-ffi

A Ruby library for using [libyara](https://yara.readthedocs.io/en/stable/capi.html) via FFI.

## Installation

Add this line to your application's Gemfile:

```ruby
gem "yara"
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install yara-ffi

## Usage

```ruby
Yara.start # run before you start using the Yara API.

rule = <<-RULE
rule ExampleRule
{
meta:
    string_meta = "an example rule for testing"

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
result = scanner.call("one day we were here and then we were not").first
result.match?
# => true

scanner.close   # run when you are done using the scanner API and want to free up memory.
Yara.stop       # run when you are completely done using the Yara API to free up memory.
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/jonmagic/yara-ffi. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](https://github.com/jonmagic/yara-ffi/blob/master/CODE_OF_CONDUCT.md).

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the Yara::Ffi project's codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/jonmagic/yara-ffi/blob/master/CODE_OF_CONDUCT.md).
