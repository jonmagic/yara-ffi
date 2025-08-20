module Yara
  # Public: Represents a single pattern match found during YARA scanning.
  #
  # A PatternMatch contains detailed information about where and how a specific
  # YARA pattern matched within the scanned data. This includes the exact offset
  # and length of the match, allowing for precise forensic analysis and data
  # extraction.
  #
  # PatternMatch instances are typically created internally during the scanning
  # process and accessed through ScanResult methods like pattern_matches.
  #
  # Examples
  #
  #   # Access pattern matches through scan results
  #   results.each do |result|
  #     result.pattern_matches.each do |pattern_name, matches|
  #       matches.each do |match|
  #         puts "Pattern #{pattern_name} matched at offset #{match.offset}"
  #         puts "Matched text: '#{match.matched_data(scanned_data)}'"
  #       end
  #     end
  #   end
  class PatternMatch
    # Public: The byte offset where this pattern match begins in the scanned data.
    attr_reader :offset

    # Public: The length in bytes of this pattern match.
    attr_reader :length

    # Public: Initialize a new PatternMatch.
    #
    # This constructor is typically called internally when processing YARA-X
    # match results. It captures the precise location and size of a pattern
    # match within scanned data.
    #
    # offset - An Integer byte offset where the match begins
    # length - An Integer length in bytes of the match
    #
    # Examples
    #
    #   # Typically created internally during scanning
    #   match = PatternMatch.new(42, 10)
    #   match.offset  # => 42
    #   match.length  # => 10
    def initialize(offset, length)
      @offset = offset
      @length = length
    end

    # Public: Extract the actual matched data from the scanned content.
    #
    # This method returns the exact bytes that matched the pattern by extracting
    # the appropriate slice from the original scanned data. This is useful for
    # forensic analysis, debugging rules, and understanding what triggered a match.
    #
    # data - A String containing the original data that was scanned
    #
    # Examples
    #
    #   # Extract what actually matched
    #   scan_data = "hello world test data"
    #   match = PatternMatch.new(6, 5)  # matches "world"
    #   match.matched_data(scan_data)   # => "world"
    #
    # Returns a String containing the matched bytes.
    # Returns empty String if offset/length are outside data bounds.
    def matched_data(data)
      return "" if offset < 0 || offset >= data.bytesize
      return "" if length <= 0 || offset + length > data.bytesize

      data.byteslice(offset, length)
    end

    # Public: Get the end offset of this match (exclusive).
    #
    # This convenience method calculates the byte position immediately after
    # the last byte of this match, which is useful for range operations and
    # avoiding overlapping matches.
    #
    # Examples
    #
    #   match = PatternMatch.new(10, 5)
    #   match.end_offset  # => 15
    #
    # Returns an Integer representing the end offset (exclusive).
    def end_offset
      offset + length
    end

    # Public: Check if this match overlaps with another match.
    #
    # This method determines whether two pattern matches have any overlapping
    # bytes. This is useful for analyzing complex rules with multiple patterns
    # or detecting redundant matches.
    #
    # other - Another PatternMatch instance to compare against
    #
    # Examples
    #
    #   match1 = PatternMatch.new(10, 5)  # bytes 10-14
    #   match2 = PatternMatch.new(12, 5)  # bytes 12-16
    #   match1.overlaps?(match2)  # => true
    #
    #   match3 = PatternMatch.new(20, 5)  # bytes 20-24
    #   match1.overlaps?(match3)  # => false
    #
    # Returns a Boolean indicating whether the matches overlap.
    def overlaps?(other)
      offset < other.end_offset && end_offset > other.offset
    end

    # Public: Get a human-readable string representation of this match.
    #
    # This method provides a concise string representation showing the key
    # details of the match, useful for debugging and logging purposes.
    #
    # Examples
    #
    #   match = PatternMatch.new(42, 10)
    #   match.to_s  # => "PatternMatch(offset: 42, length: 10)"
    #
    # Returns a String representation of this match.
    def to_s
      "PatternMatch(offset: #{offset}, length: #{length})"
    end

    # Public: Detailed inspection string with all attributes.
    #
    # Provides a complete string representation including all match attributes,
    # useful for debugging and development purposes.
    #
    # Examples
    #
    #   match = PatternMatch.new(42, 10)
    #   match.inspect  # => "#<Yara::PatternMatch:0x... @offset=42, @length=10>"
    #
    # Returns a String with detailed object information.
    def inspect
      "#<#{self.class}:0x#{object_id.to_s(16)} @offset=#{@offset}, @length=#{@length}>"
    end

    # Public: Compare two PatternMatch objects for equality.
    #
    # Two matches are considered equal if they have the same offset and length.
    # This is useful for deduplicating matches or comparing results.
    #
    # other - Another PatternMatch instance to compare against
    #
    # Examples
    #
    #   match1 = PatternMatch.new(10, 5)
    #   match2 = PatternMatch.new(10, 5)
    #   match1 == match2  # => true
    #
    # Returns a Boolean indicating equality.
    def ==(other)
      other.is_a?(PatternMatch) && offset == other.offset && length == other.length
    end

    # Public: Generate hash code for this match.
    #
    # Uses offset and length to generate a hash code, enabling PatternMatch
    # instances to be used as hash keys or in sets.
    #
    # Examples
    #
    #   match = PatternMatch.new(42, 10)
    #   {match => "info"}  # Can be used as hash key
    #
    # Returns an Integer hash code.
    def hash
      [offset, length].hash
    end

    # Public: Enable hash equality based on hash code.
    alias_method :eql?, :==
  end
end
