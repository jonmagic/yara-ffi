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
end
