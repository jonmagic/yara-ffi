# frozen_string_literal: true

require "test_helper"

# Comprehensive tests for pattern matching functionality in Scanner and ScanResult.
# Tests integration between Scanner scanning and detailed pattern match extraction.
class ScannerPatternMatchTest < Minitest::Test
  def simple_rule
    <<-RULE
      rule SimpleTest
      {
        meta:
          description = "Simple test rule"
          author = "test_suite"

        strings:
          $text1 = "hello"
          $text2 = "world"
          $text3 = "test"

        condition:
          any of them
      }
    RULE
  end

  def malware_detection_rule
    <<-RULE
      rule MalwareSignatures
      {
        meta:
          description = "Detects various malware patterns"
          author = "Security Team"
          version = 2
          severity = 8

        strings:
          $api_call = "GetProcAddress"
          $registry = "HKEY_LOCAL_MACHINE"
          $suspicious = "cmd.exe"
          $crypto = "CryptDecrypt"

        condition:
          2 of them
      }
    RULE
  end

  def overlapping_patterns_rule
    <<-RULE
      rule OverlapTest
      {
        meta:
          description = "Test rule with overlapping patterns"

        strings:
          $pattern1 = "testing"
          $pattern2 = "ting"

        condition:
          all of them
      }
    RULE
  end

  def repeated_pattern_rule
    <<-RULE
      rule TestRepeatedPattern
      {
        meta:
          description = "Test rule with pattern that matches multiple times"

        strings:
          $repeated = "test"

        condition:
          #repeated >= 2
      }
    RULE
  end

  def test_basic_pattern_match_functionality
    scanner = Yara::Scanner.new
    scanner.add_rule(simple_rule)
    scanner.compile

    data = "hello world"
    results = scanner.scan(data)

    assert_equal 1, results.size, "Expected exactly one rule match"

    result = results.first
    assert result.match?, "Expected rule to match"
    assert_equal "SimpleTest", result.rule_name

    # Check pattern matches were extracted
    refute_empty result.pattern_matches, "Expected pattern matches to be extracted"

    # Should have matches for $text1 and $text2 but not $text3
    assert result.pattern_matched?(:$text1), "Expected $text1 to match"
    assert result.pattern_matched?(:$text2), "Expected $text2 to match"
    refute result.pattern_matched?(:$text3), "Expected $text3 not to match"

    # Check specific match details
    hello_matches = result.matches_for_pattern(:$text1)
    assert_equal 1, hello_matches.size, "Expected exactly one match for $text1"
    assert_equal 0, hello_matches.first.offset, "Expected $text1 to match at offset 0"
    assert_equal 5, hello_matches.first.length, "Expected $text1 to match 5 characters"
    assert_equal "hello", hello_matches.first.matched_data(data)

    world_matches = result.matches_for_pattern(:$text2)
    assert_equal 1, world_matches.size, "Expected exactly one match for $text2"
    assert_equal 6, world_matches.first.offset, "Expected $text2 to match at offset 6"
    assert_equal 5, world_matches.first.length, "Expected $text2 to match 5 characters"
    assert_equal "world", world_matches.first.matched_data(data)

    # Test convenience methods
    assert_equal 2, result.total_matches, "Expected 2 total matches"

    all_matches = result.all_matches
    assert_equal 2, all_matches.size, "Expected 2 matches in all_matches"
    assert_equal 0, all_matches[0].offset, "Expected first match at offset 0"
    assert_equal 6, all_matches[1].offset, "Expected second match at offset 6"

    scanner.close
  end

  def test_comprehensive_malware_detection_pattern_matching
    # Sample data that contains multiple suspicious patterns
    suspicious_data = <<~DATA
      This file contains GetProcAddress calls for dynamic loading.
      It also modifies HKEY_LOCAL_MACHINE registry keys.
      The malware spawns cmd.exe processes and uses CryptDecrypt APIs.
      Another GetProcAddress call appears later in the code.
    DATA

    # Create scanner and scan
    scanner = Yara::Scanner.new
    scanner.add_rule(malware_detection_rule)
    scanner.compile

    results = scanner.scan(suspicious_data)

    assert_equal 1, results.size, "Expected exactly one rule match"
    result = results.first

    # Verify basic match info
    assert result.match?, "Expected rule to match"
    assert_equal "MalwareSignatures", result.rule_name
    assert_equal "Detects various malware patterns", result.rule_meta[:description]
    assert_equal 8, result.rule_meta[:severity]
    assert_equal 5, result.total_matches

    # Verify pattern match details were extracted
    refute_empty result.pattern_matches, "Expected pattern matches to be extracted"

    # Verify all expected patterns matched
    assert result.pattern_matched?(:$api_call), "Expected API call pattern to match"
    assert result.pattern_matched?(:$registry), "Expected registry pattern to match"
    assert result.pattern_matched?(:$suspicious), "Expected suspicious pattern to match"
    assert result.pattern_matched?(:$crypto), "Expected crypto pattern to match"

    # Verify API call matches (should appear twice)
    api_matches = result.matches_for_pattern(:$api_call)
    assert_equal 2, api_matches.size, "Expected 2 API call matches"
    assert_equal 19, api_matches[0].offset, "Expected first API call at offset 19"
    assert_equal 185, api_matches[1].offset, "Expected second API call at offset 185"
    assert_equal "GetProcAddress", api_matches[0].matched_data(suspicious_data)
    assert_equal "GetProcAddress", api_matches[1].matched_data(suspicious_data)

    # Verify registry match
    registry_matches = result.matches_for_pattern(:$registry)
    assert_equal 1, registry_matches.size, "Expected 1 registry match"
    assert_equal 78, registry_matches.first.offset, "Expected registry match at offset 78"
    assert_equal "HKEY_LOCAL_MACHINE", registry_matches.first.matched_data(suspicious_data)

    # Verify suspicious process match
    cmd_matches = result.matches_for_pattern(:$suspicious)
    assert_equal 1, cmd_matches.size, "Expected 1 cmd.exe match"
    assert_equal 131, cmd_matches.first.offset, "Expected cmd.exe match at offset 131"
    assert_equal "cmd.exe", cmd_matches.first.matched_data(suspicious_data)

    # Verify crypto match
    crypto_matches = result.matches_for_pattern(:$crypto)
    assert_equal 1, crypto_matches.size, "Expected 1 crypto match"
    assert_equal 158, crypto_matches.first.offset, "Expected crypto match at offset 158"
    assert_equal "CryptDecrypt", crypto_matches.first.matched_data(suspicious_data)

    # Verify all_matches functionality
    all_matches = result.all_matches
    assert_equal 5, all_matches.size, "Expected 5 total matches in all_matches"
    assert_equal 19, all_matches.first.offset, "Expected first match at offset 19"
    assert_equal 185, all_matches.last.offset, "Expected last match at offset 185"

    # Verify coverage calculation
    coverage = ((all_matches.last.end_offset - all_matches.first.offset).to_f / suspicious_data.length * 100).round(1)
    assert_in_delta 77.6, coverage, 0.1, "Expected approximately 77.6% coverage"

    scanner.close
  end

  def test_overlapping_pattern_matches
    scanner = Yara::Scanner.new
    scanner.add_rule(overlapping_patterns_rule)
    scanner.compile

    data = "We are testing this functionality"
    results = scanner.scan(data)

    assert_equal 1, results.size, "Expected exactly one rule match"

    result = results.first
    assert result.match?, "Expected rule to match"

    # Both patterns should match
    assert result.pattern_matched?(:$pattern1), "Expected $pattern1 to match"
    assert result.pattern_matched?(:$pattern2), "Expected $pattern2 to match"

    pattern1_matches = result.matches_for_pattern(:$pattern1)
    pattern2_matches = result.matches_for_pattern(:$pattern2)

    assert_equal 1, pattern1_matches.size, "Expected 1 long match"
    assert_equal 1, pattern2_matches.size, "Expected 1 short match"

    long_match = pattern1_matches.first
    short_match = pattern2_matches.first

    assert_equal 7, long_match.offset, "Expected long match at offset 7"
    assert_equal 7, long_match.length, "Expected long match to be 7 chars"
    assert_equal "testing", long_match.matched_data(data)

    assert_equal 10, short_match.offset, "Expected short match at offset 10"
    assert_equal 4, short_match.length, "Expected short match to be 4 chars"
    assert_equal "ting", short_match.matched_data(data)

    # Verify overlap detection works
    assert long_match.overlaps?(short_match), "Expected patterns to overlap"
    assert short_match.overlaps?(long_match), "Expected overlap to be symmetric"

    scanner.close
  end

  def test_repeated_pattern_matches
    scanner = Yara::Scanner.new
    scanner.add_rule(repeated_pattern_rule)
    scanner.compile

    data = "test data with test pattern and another test here"
    results = scanner.scan(data)

    assert_equal 1, results.size, "Expected exactly one rule match"

    result = results.first
    assert result.match?, "Expected rule to match"

    # Should have multiple matches for the same pattern
    test_matches = result.matches_for_pattern(:$repeated)
    assert_equal 3, test_matches.size, "Expected 3 matches for $repeated pattern"

    # Check each match location
    expected_offsets = [0, 15, 40]  # Positions of "test" in the data
    test_matches.sort_by(&:offset).each_with_index do |match, i|
      assert_equal expected_offsets[i], match.offset, "Expected match #{i} at offset #{expected_offsets[i]}"
      assert_equal 4, match.length, "Expected all matches to be 4 characters"
      assert_equal "test", match.matched_data(data), "Expected all matches to be 'test'"
    end

    assert_equal 3, result.total_matches, "Expected 3 total matches"

    scanner.close
  end

  def test_pattern_matches_with_string_and_symbol_keys
    scanner = Yara::Scanner.new
    scanner.add_rule(simple_rule)
    scanner.compile

    data = "hello world"
    results = scanner.scan(data)
    result = results.first

    # Test that both string and symbol keys work
    matches_with_symbol = result.matches_for_pattern(:$text1)
    matches_with_string = result.matches_for_pattern("$text1")

    assert_equal matches_with_symbol.size, matches_with_string.size, "Expected same results for symbol and string keys"

    # Test pattern_matched? with both key types
    assert result.pattern_matched?(:$text1), "Expected symbol key to work with pattern_matched?"
    assert result.pattern_matched?("$text1"), "Expected string key to work with pattern_matched?"

    scanner.close
  end

  def test_no_matches_for_nonexistent_pattern
    scanner = Yara::Scanner.new
    scanner.add_rule(simple_rule)
    scanner.compile

    data = "hello world"
    results = scanner.scan(data)
    result = results.first

    # Test accessing non-existent pattern
    matches = result.matches_for_pattern(:$nonexistent)
    assert_empty matches, "Expected empty array for non-existent pattern"

    refute result.pattern_matched?(:$nonexistent), "Expected false for non-existent pattern"

    scanner.close
  end

  def test_pattern_matches_preserved_across_block_and_return_modes
    scanner = Yara::Scanner.new
    scanner.add_rule(simple_rule)
    scanner.compile

    data = "hello world"

    # Test block mode
    block_results = []
    scanner.scan(data) do |result|
      block_results << result
      assert_equal 2, result.total_matches, "Expected pattern matches in block mode"
    end

    # Test return mode
    return_results = scanner.scan(data)

    # Both modes should give equivalent results
    assert_equal block_results.size, return_results.size
    assert_equal block_results.first.total_matches, return_results.first.total_matches
    assert_equal block_results.first.pattern_matches.keys.sort, return_results.first.pattern_matches.keys.sort

    scanner.close
  end

  def test_binary_data_pattern_matching
    # Test with binary data using string patterns
    binary_rule = <<-RULE
      rule BinaryTest
      {
        strings:
          $text1 = "ABC"
          $text2 = "test"

        condition:
          any of them
      }
    RULE

    scanner = Yara::Scanner.new
    scanner.add_rule(binary_rule)
    scanner.compile

    # Data with patterns
    data = "ABC test data"
    results = scanner.scan(data)

    assert_equal 1, results.size, "Expected exactly one rule match"

    result = results.first

    # Both patterns should match
    assert result.pattern_matched?(:$text1), "Expected text1 pattern to match"
    assert result.pattern_matched?(:$text2), "Expected text2 pattern to match"

    text1_matches = result.matches_for_pattern(:$text1)
    text2_matches = result.matches_for_pattern(:$text2)

    assert_equal 1, text1_matches.size, "Expected one text1 match"
    assert_equal 1, text2_matches.size, "Expected one text2 match"

    # Verify first match details
    text1_match = text1_matches.first
    assert_equal 0, text1_match.offset, "Expected text1 match at offset 0"
    assert_equal 3, text1_match.length, "Expected text1 match to be 3 bytes"
    assert_equal "ABC", text1_match.matched_data(data)

    # Verify second match details
    text2_match = text2_matches.first
    assert_equal 4, text2_match.offset, "Expected text2 match at offset 4"
    assert_equal 4, text2_match.length, "Expected text2 match to be 4 bytes"
    assert_equal "test", text2_match.matched_data(data)

    scanner.close
  end

  def test_enhanced_vs_basic_functionality_comparison
    rule = <<-RULE
      rule ComparisonTest
      {
        strings:
          $test1 = "hello"
          $test2 = "world"

        condition:
          any of them
      }
    RULE

    data = "Say hello to the world"

    scanner = Yara::Scanner.new
    scanner.add_rule(rule)
    scanner.compile
    results = scanner.scan(data)
    result = results.first

    # Verify enhanced capabilities work
    assert result.match?, "Expected rule to match"
    assert_equal "ComparisonTest", result.rule_name
    assert_equal 2, result.total_matches, "Expected 2 pattern matches"

    # Verify pattern-specific matching
    assert result.pattern_matched?(:$test1), "Expected $test1 to match"
    assert result.pattern_matched?(:$test2), "Expected $test2 to match"

    # Verify exact match locations
    hello_matches = result.matches_for_pattern(:$test1)
    world_matches = result.matches_for_pattern(:$test2)

    assert_equal 1, hello_matches.size, "Expected one hello match"
    assert_equal 1, world_matches.size, "Expected one world match"

    assert_equal 4, hello_matches.first.offset, "Expected hello at offset 4"
    assert_equal 17, world_matches.first.offset, "Expected world at offset 17"

    assert_equal "hello", hello_matches.first.matched_data(data)
    assert_equal "world", world_matches.first.matched_data(data)

    scanner.close
  end
end
