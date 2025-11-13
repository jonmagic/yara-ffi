# frozen_string_literal: true

require "test_helper"

class RuleIterationTest < Minitest::Test
  def rule_with_metadata
    <<-RULE
      rule TestRule
      {
        meta:
          author = "test_author"
          description = "Test rule with metadata"
          severity = 5
          is_malware = true

        strings:
          $test = "pattern"

        condition:
          $test
      }
    RULE
  end

  def rule_with_tags
    <<-RULE
      rule TaggedRule : malware trojan
      {
        meta:
          description = "Rule with tags"

        strings:
          $test = "pattern"

        condition:
          $test
      }
    RULE
  end

  def rule_in_namespace
    <<-RULE
      rule NamespacedRule
      {
        meta:
          type = "namespace_test"

        strings:
          $test = "pattern"

        condition:
          $test
      }
    RULE
  end

  def test_can_iterate_rules_without_scanning
    scanner = Yara::Scanner.new
    scanner.add_rule(rule_with_metadata)
    scanner.compile

    rules = []
    scanner.each_rule do |rule|
      rules << rule
    end

    assert_equal 1, rules.size
    assert_equal "TestRule", rules.first.identifier
    scanner.close
  end

  def test_can_access_rule_identifier
    scanner = Yara::Scanner.new
    scanner.add_rule(rule_with_metadata)
    scanner.compile

    rule = scanner.each_rule.first
    assert_equal "TestRule", rule.identifier
    scanner.close
  end

  def test_can_access_rule_namespace
    scanner = Yara::Scanner.new
    scanner.add_rule(rule_in_namespace)
    scanner.compile

    rule = scanner.each_rule.first
    # YARA-X returns "default" for default namespace
    assert_equal "default", rule.namespace
    scanner.close
  end

  def test_can_access_rule_metadata
    scanner = Yara::Scanner.new
    scanner.add_rule(rule_with_metadata)
    scanner.compile

    rule = scanner.each_rule.first
    metadata = rule.metadata
    assert_equal "test_author", metadata[:author]
    assert_equal "Test rule with metadata", metadata[:description]
    assert_equal 5, metadata[:severity]
    assert_equal true, metadata[:is_malware]
    scanner.close
  end

  def test_can_access_rule_tags
    scanner = Yara::Scanner.new
    scanner.add_rule(rule_with_tags)
    scanner.compile

    rule = scanner.each_rule.first
    tags = rule.tags
    assert_equal 2, tags.size
    assert_includes tags, "malware"
    assert_includes tags, "trojan"
    scanner.close
  end

  def test_can_iterate_multiple_rules
    scanner = Yara::Scanner.new
    scanner.add_rule(rule_with_metadata)
    scanner.add_rule(rule_with_tags)
    scanner.compile

    identifiers = []
    scanner.each_rule do |rule|
      identifiers << rule.identifier
    end

    assert_equal 2, identifiers.size
    assert_includes identifiers, "TestRule"
    assert_includes identifiers, "TaggedRule"
    scanner.close
  end

  def test_rule_iteration_without_block_returns_enumerator
    scanner = Yara::Scanner.new
    scanner.add_rule(rule_with_metadata)
    scanner.compile

    enumerator = scanner.each_rule
    assert_instance_of Enumerator, enumerator

    rules = enumerator.to_a
    assert_equal 1, rules.size
    assert_equal "TestRule", rules.first.identifier
    scanner.close
  end

  def test_raises_error_if_not_compiled
    scanner = Yara::Scanner.new
    scanner.add_rule(rule_with_metadata)

    assert_raises(Yara::Scanner::NotCompiledError) do
      scanner.each_rule { |_rule| }
    end
    scanner.close
  end
end
