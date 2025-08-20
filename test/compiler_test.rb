# frozen_string_literal: true

require "test_helper"

class CompilerTest < Minitest::Test
  def simple_rule_with_global
    <<-RULE
      rule TestWithGlobal
      {
        condition:
          RETRIES == 3
      }
    RULE
  end

  def test_create_compiler_define_globals_and_build
    compiler = Yara::Compiler.new
    # Define globals before adding source
    compiler.define_global_int("RETRIES", 3)
    compiler.add_source(simple_rule_with_global)
    rules_ptr = compiler.build
    refute_nil rules_ptr

    # Create scanner from rules and scan some data
    scanner_ptr_holder = ::FFI::MemoryPointer.new(:pointer)
    result = Yara::FFI.yrx_scanner_create(rules_ptr, scanner_ptr_holder)
    assert_equal Yara::FFI::YRX_SUCCESS, result
    scanner_ptr = scanner_ptr_holder.get_pointer(0)

    # Clean up
    Yara::FFI.yrx_scanner_destroy(scanner_ptr)
    Yara::FFI.yrx_rules_destroy(rules_ptr)
    compiler.destroy
  end

  def test_scanner_from_rules_build_and_scan
    compiler = Yara::Compiler.new
    compiler.define_global_int("RETRIES", 3)
    compiler.add_source(simple_rule_with_global)
    rules_ptr = compiler.build

    scanner = Yara::Scanner.from_rules(rules_ptr, owns_rules: true)
    # No explicit compile needed; scanner is ready to use
    results = scanner.scan("")

    # Clean up via Scanner.close (owns_rules: true will destroy rules)
    scanner.close
    compiler.destroy
  end
end
