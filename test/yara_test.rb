# frozen_string_literal: true

require "test_helper"

class YaraTest < Minitest::Test
  def test_that_it_has_a_version_number
    refute_nil ::Yara::VERSION
  end

  def rule
    <<-RULE
      rule ExampleRule
      {
        meta:
          string_meta = "an example rule for testing"
          false_meta = false
          true_meta = true
          int_meta = 123

        strings:
          $my_text_string = "we were here"
          $my_text_regex = /were here/

        condition:
          $my_text_string or $my_text_regex
      }
    RULE
  end

  def test_rule_that_matches
    result = Yara.test(rule, "i think we were here that one time").first
    assert result.match?
  end

  def test_rule_that_does_not_match
    results = Yara.test(rule, "we were never here i'm pretty sure")
    assert_empty results
  end

  def test_rule_meta_parsing
    result = Yara.test(rule, "i think we were here that one time").first
    expected_meta = {
      string_meta: "an example rule for testing",
      false_meta: false,
      true_meta: true,
      int_meta: 123
    }
    assert_equal expected_meta, result.rule_meta
  end

  def test_rule_string_parsing
    result = Yara.test(rule, "i think we were here that one time").first
    expected_strings = {
      "$my_text_string": "we were here",
      "$my_text_regex": "were here",
    }
    assert_equal expected_strings, result.rule_strings
  end

  def test_string_with_null_byte
    results = Yara.test(rule, "hi\000")
    assert_empty results
  end
end
