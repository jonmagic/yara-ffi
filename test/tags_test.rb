# frozen_string_literal: true

require "test_helper"

# Tests for YARA rule tags functionality.
# Tests the extraction and querying of tags attached to YARA rules.
class TagsTest < Minitest::Test
  def rule_with_tags
    <<-RULE
      rule TaggedRule : malware suspicious windows
      {
        meta:
          author = "Security Team"
          description = "Test rule with tags"
          severity = 7
          active = true

        strings:
          $api_call = "GetProcAddress"
          $registry = "HKEY_CURRENT_USER"

        condition:
          any of them
      }
    RULE
  end

  def rule_without_tags
    <<-RULE
      rule UntaggedRule
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

  def test_tags_are_extracted_from_rule
    scanner = Yara::Scanner.new
    scanner.add_rule(rule_with_tags)
    scanner.compile

    data = "This contains GetProcAddress call"
    results = scanner.scan(data)

    assert_equal 1, results.size
    result = results.first

    # Test tag array is populated
    assert result.tags.is_a?(Array), "Expected tags to be an array"
    refute_empty result.tags, "Expected tags to be extracted from rule"

    # Test specific tags are present
    assert_includes result.tags, "malware"
    assert_includes result.tags, "suspicious"
    assert_includes result.tags, "windows"
    assert_equal 3, result.tags.size

    scanner.close
  end

  def test_has_tag_method_functionality
    scanner = Yara::Scanner.new
    scanner.add_rule(rule_with_tags)
    scanner.compile

    data = "This contains GetProcAddress call"
    results = scanner.scan(data)
    result = results.first

    # Test has_tag? method works correctly
    assert result.has_tag?("malware")
    assert result.has_tag?("suspicious")
    assert result.has_tag?("windows")

    # Test negative cases
    refute result.has_tag?("linux")
    refute result.has_tag?("trojan")
    refute result.has_tag?("nonexistent")

    scanner.close
  end

  def test_rule_without_tags
    scanner = Yara::Scanner.new
    scanner.add_rule(rule_without_tags)
    scanner.compile

    data = "This contains test"
    results = scanner.scan(data)
    result = results.first

    # Test that rules without tags have empty tag arrays
    assert result.tags.is_a?(Array), "Expected tags to be an array"
    assert_empty result.tags, "Expected no tags for untagged rule"

    # Test has_tag? returns false for any tag
    refute result.has_tag?("malware")
    refute result.has_tag?("any_tag")

    scanner.close
  end

  def test_multiple_rules_with_different_tags
    rule1 = <<-RULE
      rule FirstRule : malware
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
      rule SecondRule : trojan backdoor
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

    assert first_result, "Expected FirstRule to match"
    assert second_result, "Expected SecondRule to match"

    # Test tags are properly extracted for both rules
    assert first_result.tags.is_a?(Array)
    assert second_result.tags.is_a?(Array)

    # Test specific tags for each rule
    assert first_result.has_tag?("malware"), "FirstRule should have malware tag"
    assert_equal 1, first_result.tags.size

    assert second_result.has_tag?("trojan"), "SecondRule should have trojan tag"
    assert second_result.has_tag?("backdoor"), "SecondRule should have backdoor tag"
    assert_equal 2, second_result.tags.size

    # Test cross-contamination doesn't occur
    refute first_result.has_tag?("trojan")
    refute first_result.has_tag?("backdoor")
    refute second_result.has_tag?("malware")

    scanner.close
  end

  def test_tags_work_with_pattern_matching
    # Ensure tags functionality doesn't interfere with pattern matching
    scanner = Yara::Scanner.new
    scanner.add_rule(rule_with_tags)
    scanner.compile

    data = "This contains GetProcAddress and HKEY_CURRENT_USER"
    results = scanner.scan(data)
    result = results.first

    # Test both tags and pattern matching work together
    assert result.has_tag?("malware")
    assert result.pattern_matched?(:$api_call)
    assert result.pattern_matched?(:$registry)

    api_matches = result.matches_for_pattern(:$api_call)
    registry_matches = result.matches_for_pattern(:$registry)

    assert_equal 1, api_matches.size
    assert_equal 1, registry_matches.size
    assert_equal 3, result.tags.size

    scanner.close
  end

  def test_has_tag_error_handling
    scanner = Yara::Scanner.new
    scanner.add_rule(rule_with_tags)
    scanner.compile

    data = "This contains GetProcAddress call"
    results = scanner.scan(data)
    result = results.first

    # Test that has_tag? handles edge cases gracefully
    refute result.has_tag?(nil), "has_tag? should return false for nil"
    refute result.has_tag?(""), "has_tag? should return false for empty string"

    # Test that no exceptions are raised
    begin
      result.has_tag?(nil)
      result.has_tag?("")
      result.has_tag?("nonexistent")
      assert true, "has_tag? handled edge cases without raising errors"
    rescue => e
      flunk "has_tag? should handle edge cases gracefully, but raised: #{e.message}"
    end

    scanner.close
  end

  def test_tags_preserve_backwards_compatibility
    # Ensure tags functionality doesn't break existing API
    scanner = Yara::Scanner.new
    scanner.add_rule(rule_with_tags)
    scanner.compile

    data = "This contains GetProcAddress call"
    results = scanner.scan(data)
    result = results.first

    # Test existing API methods still work alongside tags
    assert result.match?, "Expected rule to match"
    assert_equal "TaggedRule", result.rule_name
    assert_kind_of Hash, result.rule_meta
    assert_kind_of Hash, result.rule_strings
    assert_kind_of Hash, result.pattern_matches

    # Test enhanced features work together
    assert result.has_tag?("malware")
    assert_equal "Security Team", result.rule_meta[:author]

    scanner.close
  end
end
