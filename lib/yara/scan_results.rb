module Yara
  class ScanResults
    include Enumerable

    def initialize(results = [])
      @results = results
    end

    def each(&block)
      @results.each(&block)
    end

    def <<(result)
      @results << result
    end

    def matches
      @results
    end

    def matching_rules
      @results.map(&:rule_name)
    end

    def matched?
      !@results.empty?
    end

    alias_method :match?, :matched?

    def size
      @results.size
    end

    alias_method :length, :size
    alias_method :count, :size

    def first
      @results.first
    end

    def last
      @results.last
    end

    def empty?
      @results.empty?
    end

    def to_a
      @results.dup
    end
  end
end
