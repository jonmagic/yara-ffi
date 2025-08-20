# frozen_string_literal: true

require "test_helper"

class SerializeTest < Minitest::Test
  def rule_simple
    <<-RULE
      rule SerializedRule
      {
        strings:
          $s = "hello"
        condition:
          $s
      }
    RULE
  end

  def test_compile_serialize_deserialize_and_scan
    compiler = Yara::Compiler.new
    compiler.add_source(rule_simple)
    serialized = compiler.build_serialized
    refute_nil serialized
    assert_kind_of String, serialized
    assert serialized.bytesize > 0

    scanner = Yara::Scanner.from_serialized(serialized, owns_rules: true)
    results = scanner.scan("hello world")
    assert_predicate results.first, :match?

    scanner.close
    compiler.destroy
  end
end
