# frozen_string_literal: true

require "test_helper"
require "open3"
require "rbconfig"

class RuntimeDependenciesTest < Minitest::Test
  def test_loads_without_development_dependencies
    root = File.expand_path("..", __dir__)
    script = <<~RUBY
      require "bundler"
      Bundler.setup(:default) # see https://docs.ruby-lang.org/en/4.0/Bundler.html#method-c-setup
      require "yara"
    RUBY

    # The subprocess runs in an unbundled env, otherwise would make Bundler
    # activate every group anyway.
    _out, err, status = Bundler.with_unbundled_env do
      Open3.capture3(
        RbConfig.ruby,                # current ruby executable abs path
        "-I", File.join(root, "lib"), # include gem's `lib/` path in `$LOAD_PATH`
        "-e", script,                 # script to execute
        chdir: root                   # see https://docs.ruby-lang.org/en/4.0/Process.html#module-Process-label-Execution%20Options
      )
    end

    assert status.success?, -> { err }
  end
end
