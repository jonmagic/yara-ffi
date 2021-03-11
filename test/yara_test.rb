# frozen_string_literal: true

require "test_helper"

class YaraTest < Minitest::Test
  def test_that_it_has_a_version_number
    refute_nil ::Yara::VERSION
  end
end
