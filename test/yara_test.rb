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
        strings:
          $my_text_string = "we were here"

        condition:
          $my_text_string
      }
    RULE
  end

  def test_rule_that_matches
    expected_results = ["ExampleRule"]
    assert_equal expected_results, Yara.test(rule, "i think we were here that one time")
  end

  def test_rule_that_does_not_match
    expected_results = []
    assert_equal expected_results, Yara.test(rule, "we were never here i'm pretty sure")
  end
end
