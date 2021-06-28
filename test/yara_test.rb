# frozen_string_literal: true

require "test_helper"

class YaraTest < Minitest::Test
  def test_that_it_has_a_version_number
    refute_nil ::Yara::VERSION
  end

  def test_that_it_works
    # https://yara.readthedocs.io/en/v3.7.0/writingrules.html#writing-yara-rules
    rule = <<-RULE
      rule dummy
      {
          condition:
              false
      }
    RULE
    assert_equal 0, Yara.test(rule, "test string")
  end
end
