# frozen_string_literal: true

require "test_helper"

# Tests for YARA rule metadata access functionality.
# Tests the type-safe metadata accessor methods and their integration with pattern matching.
class MetadataTest < Minitest::Test
  def rule_with_metadata
    <<-RULE
      rule MetadataRule : malware suspicious
      {
        meta:
          author = "Security Team"
          description = "Test rule with various metadata types"
          severity = 7
          active = true
          confidence = 0.85
          version = 2

        strings:
          $api_call = "GetProcAddress"
          $registry = "HKEY_CURRENT_USER"

        condition:
          any of them
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

  def test_enhanced_metadata_accessors
    # Test the new type-safe metadata accessor methods
    scanner = Yara::Scanner.new
    scanner.add_rule(rule_with_metadata)
    scanner.compile

    data = "This contains GetProcAddress call"
    results = scanner.scan(data)

    assert_equal 1, results.size
    result = results.first

    # Test metadata_value generic accessor
    assert_equal "Security Team", result.metadata_value(:author)
    assert_equal "Test rule with various metadata types", result.metadata_value(:description)
    assert_equal 7, result.metadata_value(:severity)
    assert_equal true, result.metadata_value(:active)
    assert_equal 2, result.metadata_value(:version)

    # Test type-specific accessors
    assert_equal "Security Team", result.metadata_string(:author)
    assert_equal "Test rule with various metadata types", result.metadata_string(:description)
    assert_equal 7, result.metadata_int(:severity)
    assert_equal 2, result.metadata_int(:version)
    assert_equal true, result.metadata_bool(:active)

    # Test that type-specific accessors return nil for wrong types
    assert_nil result.metadata_int(:author)      # author is string, not int
    assert_nil result.metadata_bool(:severity)   # severity is int, not bool
    assert_nil result.metadata_string(:severity) # severity is int, not string

    # Test non-existent metadata
    assert_nil result.metadata_value(:nonexistent)
    assert_nil result.metadata_string(:nonexistent)
    assert_nil result.metadata_int(:nonexistent)
    assert_nil result.metadata_bool(:nonexistent)

    scanner.close
  end

  def test_enhanced_pattern_matching_with_metadata
    # Ensure enhanced metadata doesn't break existing pattern matching functionality
    scanner = Yara::Scanner.new
    scanner.add_rule(rule_with_metadata)
    scanner.compile

    data = "This contains GetProcAddress and HKEY_CURRENT_USER"
    results = scanner.scan(data)

    assert_equal 1, results.size
    result = results.first

    # Test enhanced pattern matching still works
    assert result.pattern_matched?(:$api_call), "Expected API call pattern to match"
    assert result.pattern_matched?(:$registry), "Expected registry pattern to match"

    api_matches = result.matches_for_pattern(:$api_call)
    registry_matches = result.matches_for_pattern(:$registry)

    assert_equal 1, api_matches.size, "Expected one API call match"
    assert_equal 1, registry_matches.size, "Expected one registry match"

    assert_equal "GetProcAddress", api_matches.first.matched_data(data)
    assert_equal "HKEY_CURRENT_USER", registry_matches.first.matched_data(data)

    assert_equal 2, result.total_matches, "Expected 2 total matches"

    # Test metadata is still accessible
    assert_equal "Security Team", result.metadata_string(:author)
    assert_equal 7, result.metadata_int(:severity)

    scanner.close
  end

  def test_backwards_compatibility_with_existing_api
    # Ensure all existing ScanResult methods still work
    scanner = Yara::Scanner.new
    scanner.add_rule(rule_with_metadata)
    scanner.compile

    data = "This contains GetProcAddress call"
    results = scanner.scan(data)

    result = results.first

    # Test existing API methods still work
    assert result.match?, "Expected rule to match"
    assert_equal "MetadataRule", result.rule_name
    assert_kind_of Hash, result.rule_meta
    assert_kind_of Hash, result.rule_strings
    assert_kind_of Hash, result.pattern_matches

    # Test existing metadata access still works
    assert_equal "Security Team", result.rule_meta[:author]
    assert_equal 7, result.rule_meta[:severity]

    # Test enhanced metadata accessors work alongside existing API
    assert_equal "Security Team", result.metadata_string(:author)
    assert_equal 7, result.metadata_int(:severity)

    scanner.close
  end

  def test_enhanced_features_with_no_matches
    # Test enhanced features work even when rule doesn't match
    scanner = Yara::Scanner.new
    scanner.add_rule(rule_with_metadata)
    scanner.compile

    data = "This data contains no suspicious patterns"
    results = scanner.scan(data)

    # Should be no matches
    assert_empty results, "Expected no matches for clean data"

    scanner.close
  end

  def test_multiple_metadata_types
    # Test handling of different metadata value types
    complex_rule = <<-RULE
      rule ComplexMetadataRule
      {
        meta:
          name = "TestRule"
          priority = 10
          enabled = false
          threshold = 0.75

        strings:
          $test = "sample"

        condition:
          $test
      }
    RULE

    scanner = Yara::Scanner.new
    scanner.add_rule(complex_rule)
    scanner.compile

    data = "This contains sample text"
    results = scanner.scan(data)
    result = results.first

    # Test different metadata types are handled correctly
    assert_equal "TestRule", result.metadata_string(:name)
    assert_equal 10, result.metadata_int(:priority)
    assert_equal false, result.metadata_bool(:enabled)

    # Test type mismatches return nil
    assert_nil result.metadata_int(:name)        # name is string
    assert_nil result.metadata_bool(:priority)   # priority is int
    assert_nil result.metadata_string(:enabled)  # enabled is bool

    scanner.close
  end

  def test_pattern_matches_preserved_with_metadata_enhancements
    # Verify that the detailed pattern match information is preserved
    # with the new enhanced metadata features
    scanner = Yara::Scanner.new
    scanner.add_rule(rule_with_metadata)
    scanner.compile

    data = "Start GetProcAddress middle HKEY_CURRENT_USER end"
    results = scanner.scan(data)

    result = results.first

    # Verify pattern match details are still accurate
    api_matches = result.matches_for_pattern(:$api_call)
    registry_matches = result.matches_for_pattern(:$registry)

    assert_equal 1, api_matches.size
    assert_equal 1, registry_matches.size

    api_match = api_matches.first
    registry_match = registry_matches.first

    # Check exact offsets are correct
    assert_equal 6, api_match.offset, "Expected GetProcAddress at offset 6"
    assert_equal 14, api_match.length, "Expected GetProcAddress length 14"
    assert_equal "GetProcAddress", api_match.matched_data(data)

    assert_equal 28, registry_match.offset, "Expected HKEY_CURRENT_USER at offset 28"
    assert_equal 17, registry_match.length, "Expected HKEY_CURRENT_USER length 17"
    assert_equal "HKEY_CURRENT_USER", registry_match.matched_data(data)

    # Test convenience methods work
    all_matches = result.all_matches
    assert_equal 2, all_matches.size
    assert_equal 6, all_matches.first.offset
    assert_equal 28, all_matches.last.offset

    # Test metadata is accessible alongside pattern matching
    assert_equal "Security Team", result.metadata_string(:author)
    assert_equal 7, result.metadata_int(:severity)

    scanner.close
  end

  def test_metadata_error_handling
    # Test that enhanced metadata methods handle errors gracefully
    scanner = Yara::Scanner.new
    scanner.add_rule(simple_rule)
    scanner.compile

    data = "This contains test"
    results = scanner.scan(data)
    result = results.first

    # Test that methods don't raise errors for edge cases
    begin
      result.metadata_value(nil)
      result.metadata_string("")
      result.metadata_int(:nonexistent)
      result.metadata_bool(:missing)
      # If we get here without exception, the test passes
      assert true, "Methods handled edge cases without raising errors"
    rescue => e
      flunk "Methods should handle edge cases gracefully, but raised: #{e.message}"
    end

    # Test nil/empty string handling
    assert_nil result.metadata_value(nil)
    assert_nil result.metadata_string("")
    assert_nil result.metadata_int(:nonexistent)
    assert_nil result.metadata_bool(:missing)

    scanner.close
  end
end
