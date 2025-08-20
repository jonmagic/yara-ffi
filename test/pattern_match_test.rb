# frozen_string_literal: true

require "test_helper"

class PatternMatchTest < Minitest::Test
  def test_pattern_match_initialization
    match = Yara::PatternMatch.new(42, 10)
    assert_equal 42, match.offset
    assert_equal 10, match.length
  end

  def test_pattern_match_end_offset
    match = Yara::PatternMatch.new(10, 5)
    assert_equal 15, match.end_offset
  end

  def test_pattern_match_matched_data_extraction
    data = "hello world test data"
    match = Yara::PatternMatch.new(6, 5)  # Should match "world"

    assert_equal "world", match.matched_data(data)
  end

  def test_pattern_match_matched_data_bounds_checking
    data = "hello"

    # Test offset beyond data
    match1 = Yara::PatternMatch.new(10, 5)
    assert_equal "", match1.matched_data(data)

    # Test length extending beyond data
    match2 = Yara::PatternMatch.new(3, 10)
    assert_equal "", match2.matched_data(data)

    # Test negative offset
    match3 = Yara::PatternMatch.new(-1, 5)
    assert_equal "", match3.matched_data(data)

    # Test zero length
    match4 = Yara::PatternMatch.new(2, 0)
    assert_equal "", match4.matched_data(data)
  end

  def test_pattern_match_overlaps
    match1 = Yara::PatternMatch.new(10, 5)  # bytes 10-14
    match2 = Yara::PatternMatch.new(12, 5)  # bytes 12-16 (overlaps)
    match3 = Yara::PatternMatch.new(20, 5)  # bytes 20-24 (no overlap)
    match4 = Yara::PatternMatch.new(5, 6)   # bytes 5-10 (overlaps at boundary)

    assert match1.overlaps?(match2), "Expected match1 to overlap with match2"
    refute match1.overlaps?(match3), "Expected match1 not to overlap with match3"
    assert match1.overlaps?(match4), "Expected match1 to overlap with match4 at boundary"
  end

  def test_pattern_match_equality
    match1 = Yara::PatternMatch.new(10, 5)
    match2 = Yara::PatternMatch.new(10, 5)
    match3 = Yara::PatternMatch.new(10, 6)

    assert_equal match1, match2, "Expected matches with same offset/length to be equal"
    refute_equal match1, match3, "Expected matches with different length to be unequal"
  end

  def test_pattern_match_hash_and_eql
    match1 = Yara::PatternMatch.new(10, 5)
    match2 = Yara::PatternMatch.new(10, 5)
    match3 = Yara::PatternMatch.new(10, 6)

    # Test hash equality
    assert_equal match1.hash, match2.hash, "Expected equal matches to have same hash"
    refute_equal match1.hash, match3.hash, "Expected unequal matches to have different hash"

    # Test eql? (used by hash)
    assert match1.eql?(match2), "Expected eql? to be true for equal matches"
    refute match1.eql?(match3), "Expected eql? to be false for unequal matches"

    # Test as hash keys
    hash = {match1 => "first", match2 => "second"}
    assert_equal "second", hash[match1], "Expected match1 to retrieve match2's value (same key)"
  end

  def test_pattern_match_to_s_and_inspect
    match = Yara::PatternMatch.new(42, 10)

    assert_equal "PatternMatch(offset: 42, length: 10)", match.to_s
    assert_includes match.inspect, "Yara::PatternMatch"
    assert_includes match.inspect, "@offset=42"
    assert_includes match.inspect, "@length=10"
  end
end
