# frozen_string_literal: true

require "test_helper"

class ScannerTest < Minitest::Test
  def rule_one
    <<-RULE
      rule ExampleRuleOne
      {
        meta:
          description = "Example rule one"

        strings:
          $my_text_string = "one two"

        condition:
          $my_text_string
      }
    RULE
  end

  def rule_two
    <<-RULE
      rule ExampleRuleTwo
      {
        meta:
          description = "Example rule two"

        strings:
          $my_text_regex = /three four/

        condition:
          $my_text_regex
      }
    RULE
  end

  def test_compiles_rule_and_successfully_detects_match
    scanner = Yara::Scanner.new
    scanner.add_rule(rule_one)
    scanner.compile
    results = scanner.scan("one two three four")
    assert_predicate results.first, :match?
    scanner.close
  end

  def test_can_compile_multiple_rules_into_single_scanner
    scanner = Yara::Scanner.new
    scanner.add_rule(rule_one)
    scanner.add_rule(rule_two)
    scanner.compile
    results = scanner.scan("one two three four")
    assert_equal [true, true], results.map(&:match?)
    scanner.close
  end

  def test_can_compile_multiple_rules_into_separate_scanners
    scanner1 = Yara::Scanner.new
    scanner1.add_rule(rule_one)
    scanner1.compile
    scanner2 = Yara::Scanner.new
    scanner2.add_rule(rule_two)
    scanner2.compile
    results1 = scanner1.scan("one two three four")
    assert_predicate results1.first, :match?
    assert_equal 1, results1.size
    scanner1.close
    results2 = scanner2.scan("one two three four")
    assert_predicate results2.first, :match?
    assert_equal 1, results2.size
    scanner2.close
  end

  def test_can_set_scanner_timeout
    scanner = Yara::Scanner.new
    scanner.add_rule(rule_one)
    scanner.compile
    # Setting a short timeout should not raise (FFI call should succeed)
    scanner.set_timeout(1000)
    scanner.close
  end

  def test_can_set_scanner_globals
    scanner = Yara::Scanner.new
    scanner.add_rule(rule_one)
    scanner.compile

    # Each setter should be callable. If the global wasn't defined at
    # compile time the C API may return an error; that's acceptable here.
    begin
      scanner.set_global_str("ENV", "production")
    rescue Yara::Scanner::ScanError => e
      assert_match(/variable|not defined|Variable/, e.message, "Unexpected error for set_global_str: #{e.message}")
    end

    begin
      scanner.set_global_bool("ENABLED", true)
    rescue Yara::Scanner::ScanError => e
      assert_match(/variable|not defined|Variable/, e.message, "Unexpected error for set_global_bool: #{e.message}")
    end

    begin
      scanner.set_global_int("RETRIES", 3)
    rescue Yara::Scanner::ScanError => e
      assert_match(/variable|not defined|Variable/, e.message, "Unexpected error for set_global_int: #{e.message}")
    end

    begin
      scanner.set_global_float("THRESHOLD", 0.75)
    rescue Yara::Scanner::ScanError => e
      assert_match(/variable|not defined|Variable/, e.message, "Unexpected error for set_global_float: #{e.message}")
    end

    scanner.close
  end

  def test_set_globals_convenience_method_lenient_mode
    # Test that set_globals works in lenient mode when globals aren't defined
    scanner = Yara::Scanner.new
    scanner.add_rule(rule_one) # Simple rule that doesn't use globals
    scanner.compile

    # In lenient mode, undefined globals are silently ignored
    scanner.set_globals({
      "ENV" => "production",        # Undefined - will be skipped
      "DEBUG" => false,             # Undefined - will be skipped
      "RETRIES" => 3,               # Undefined - will be skipped
      "THRESHOLD" => 0.95           # Undefined - will be skipped
    }, strict: false)

    # Test that scanning still works (rule doesn't depend on globals)
    results = scanner.scan("one two three four")
    assert_predicate results.first, :match?
    scanner.close
  end

  def test_set_globals_convenience_method_strict_mode
    # Test that set_globals raises in strict mode when globals aren't defined
    scanner = Yara::Scanner.new
    scanner.add_rule(rule_one) # Simple rule that doesn't use globals
    scanner.compile

    # In strict mode (default), undefined globals should raise
    assert_raises(Yara::Scanner::ScanError) do
      scanner.set_globals({
        "UNDEFINED_GLOBAL" => "value"
      }) # strict: true is the default
    end

    scanner.close
  end

  def test_set_globals_strict_mode_error_handling
    scanner = Yara::Scanner.new
    scanner.add_rule(rule_one)
    scanner.compile

    # Test strict mode (default) - should raise on unsupported type
    assert_raises(Yara::Scanner::ScanError) do
      scanner.set_globals({
        "ENV" => "production",
        "INVALID" => Object.new  # Unsupported type
      })
    end

    scanner.close
  end

  def test_set_globals_lenient_mode_error_handling
    scanner = Yara::Scanner.new
    scanner.add_rule(rule_one)
    scanner.compile

    # Test lenient mode - should not raise on unsupported type
    exception_raised = false
    begin
      scanner.set_globals({
        "ENV" => "production",
        "VALID_STR" => "test",
        "INVALID" => Object.new  # Should be skipped silently
      }, strict: false)
    rescue => e
      exception_raised = true
    end

    refute exception_raised, "Expected no exception in lenient mode, but got one"
    scanner.close
  end
end
