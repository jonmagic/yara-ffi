# frozen_string_literal: true

require "test_helper"

# Tests for YARA rule namespace functionality.
# Tests the extraction and handling of namespaces for rule organization.
class NamespaceTest < Minitest::Test
  def namespaced_rule
    <<-RULE
      import "pe"

      rule NamespacedRule : trojan
      {
        meta:
          family = "TestFamily"
          platform = "windows"
          version = 2

        strings:
          $string1 = "malicious"

        condition:
          $string1
      }
    RULE
  end

  def simple_rule
    <<-RULE
      rule SimpleRule
      {
        meta:
          author = "Test Team"

        strings:
          $pattern = "test"

        condition:
          $pattern
      }
    RULE
  end

  def test_default_namespace_extraction
    scanner = Yara::Scanner.new
    scanner.add_rule(namespaced_rule)
    scanner.compile

    data = "This is malicious content"
    results = scanner.scan(data)

    assert_equal 1, results.size
    result = results.first

    # Test namespace attribute exists and is extracted
    assert_respond_to result, :namespace, "Expected namespace accessor to exist"
    assert_equal "default", result.namespace, "Expected default namespace for rules without explicit namespace"

    scanner.close
  end

  def test_qualified_name_functionality
    scanner = Yara::Scanner.new
    scanner.add_rule(namespaced_rule)
    scanner.compile

    data = "This is malicious content"
    results = scanner.scan(data)
    result = results.first

    # Test qualified_name method
    assert_respond_to result, :qualified_name, "Expected qualified_name method to exist"
    assert_equal "default.NamespacedRule", result.qualified_name

    scanner.close
  end

  def test_simple_rule_namespace
    scanner = Yara::Scanner.new
    scanner.add_rule(simple_rule)
    scanner.compile

    data = "This contains test"
    results = scanner.scan(data)
    result = results.first

    # Test that simple rules also get default namespace
    assert_equal "default", result.namespace
    assert_equal "default.SimpleRule", result.qualified_name

    scanner.close
  end

  def test_namespace_with_tags
    scanner = Yara::Scanner.new
    scanner.add_rule(namespaced_rule)
    scanner.compile

    data = "This is malicious content"
    results = scanner.scan(data)
    result = results.first

    # Test that namespace and tags work together
    assert_equal "default", result.namespace
    assert_includes result.tags, "trojan"
    assert_equal "default.NamespacedRule", result.qualified_name

    scanner.close
  end

  def test_multiple_rules_namespaces
    rule1 = <<-RULE
      rule FirstRule
      {
        meta:
          author = "Team A"

        strings:
          $pattern1 = "bad_stuff"

        condition:
          $pattern1
      }
    RULE

    rule2 = <<-RULE
      rule SecondRule
      {
        meta:
          author = "Team B"

        strings:
          $pattern2 = "evil_code"

        condition:
          $pattern2
      }
    RULE

    scanner = Yara::Scanner.new
    scanner.add_rule(rule1)
    scanner.add_rule(rule2)
    scanner.compile

    data = "This contains bad_stuff and evil_code"
    results = scanner.scan(data)

    assert_equal 2, results.size, "Expected both rules to match"

    # Find results by rule name
    first_result = results.find { |r| r.rule_name == "FirstRule" }
    second_result = results.find { |r| r.rule_name == "SecondRule" }

    # Test both rules have proper namespaces
    assert_equal "default", first_result.namespace
    assert_equal "default", second_result.namespace
    assert_equal "default.FirstRule", first_result.qualified_name
    assert_equal "default.SecondRule", second_result.qualified_name

    scanner.close
  end

  def test_namespace_with_pattern_matching
    # Ensure namespace functionality doesn't interfere with pattern matching
    scanner = Yara::Scanner.new
    scanner.add_rule(namespaced_rule)
    scanner.compile

    data = "This is malicious content"
    results = scanner.scan(data)
    result = results.first

    # Test both namespace and pattern matching work together
    assert_equal "default", result.namespace
    assert result.pattern_matched?(:$string1)

    string_matches = result.matches_for_pattern(:$string1)
    assert_equal 1, string_matches.size
    assert_equal "malicious", string_matches.first.matched_data(data)

    scanner.close
  end

  def test_qualified_name_edge_cases
    scanner = Yara::Scanner.new
    scanner.add_rule(simple_rule)
    scanner.compile

    data = "This contains test"
    results = scanner.scan(data)
    result = results.first

    # Test qualified_name handles various scenarios
    qualified = result.qualified_name
    assert qualified.is_a?(String), "qualified_name should return a string"
    assert qualified.include?("."), "qualified_name should include namespace separator"
    assert qualified.start_with?("default."), "qualified_name should start with namespace"
    assert qualified.end_with?("SimpleRule"), "qualified_name should end with rule name"

    scanner.close
  end

  def test_namespace_error_handling
    scanner = Yara::Scanner.new
    scanner.add_rule(simple_rule)
    scanner.compile

    data = "This contains test"
    results = scanner.scan(data)
    result = results.first

    # Test that namespace methods handle edge cases gracefully
    begin
      namespace = result.namespace
      qualified = result.qualified_name

      assert namespace.is_a?(String), "namespace should be a string"
      assert qualified.is_a?(String), "qualified_name should be a string"
      assert true, "Namespace methods handled calls without raising errors"
    rescue => e
      flunk "Namespace methods should handle calls gracefully, but raised: #{e.message}"
    end

    scanner.close
  end

  def test_namespace_preserves_backwards_compatibility
    # Ensure namespace functionality doesn't break existing API
    scanner = Yara::Scanner.new
    scanner.add_rule(namespaced_rule)
    scanner.compile

    data = "This is malicious content"
    results = scanner.scan(data)
    result = results.first

    # Test existing API methods still work alongside namespace
    assert result.match?, "Expected rule to match"
    assert_equal "NamespacedRule", result.rule_name
    assert_kind_of Hash, result.rule_meta
    assert_kind_of Hash, result.rule_strings
    assert_kind_of Hash, result.pattern_matches

    # Test enhanced features work together
    assert_equal "default", result.namespace
    assert_equal "TestFamily", result.rule_meta[:family]

    scanner.close
  end
end
