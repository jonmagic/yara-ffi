module Yara
  # Public: Represents a single rule match result from YARA scanning.
  #
  # A ScanResult contains information about a YARA rule that matched during
  # scanning, including the rule name, metadata, string patterns, and detailed
  # pattern match information. This class provides access to rule information
  # extracted from both the YARA-X API and parsed rule source code.
  #
  # The enhanced version provides detailed pattern match information including
  # exact offsets and lengths of each pattern match, allowing for precise
  # forensic analysis and data extraction.
  #
  # Examples
  #
  #   # Typically created by Scanner during scanning
  #   scanner.scan(data) do |result|
  #     puts "Matched rule: #{result.rule_name}"
  #     puts "Author: #{result.rule_meta[:author]}"
  #
  #     # New: Access detailed pattern matches
  #     result.pattern_matches.each do |pattern_name, matches|
  #       puts "Pattern #{pattern_name}: #{matches.size} matches"
  #       matches.each do |match|
  #         matched_text = data[match.offset, match.length]
  #         puts "  At offset #{match.offset}: '#{matched_text}'"
  #       end
  #     end
  #   end
  class ScanResult
    # Public: The name identifier of the matched rule.
    attr_reader :rule_name

    # Public: FFI pointer to the underlying YRX_RULE structure.
    attr_reader :rule_ptr

    # Public: Hash of metadata key-value pairs extracted from the rule.
    attr_reader :rule_meta

    # Public: Hash of string pattern names and their values from the rule.
    attr_reader :rule_strings

    # Public: Hash of pattern names to arrays of PatternMatch objects.
    #
    # This provides detailed information about exactly where each pattern
    # matched in the scanned data, including offset and length information.
    attr_reader :pattern_matches

    # Public: Initialize a new ScanResult.
    #
    # This constructor is typically called internally by Scanner when a rule
    # matches during scanning. It extracts available information from both
    # the YARA-X API and the original rule source code, including detailed
    # pattern match information.
    #
    # rule_name      - A String containing the rule identifier/name
    # rule_ptr       - An FFI Pointer to the YRX_RULE structure
    # is_match       - A Boolean indicating if this represents a match (default true)
    # rule_source    - An optional String containing the original rule source for parsing
    # scanned_data   - An optional String containing the data that was scanned (needed for pattern matches)
    #
    # Examples
    #
    #   # Typically created internally by Scanner
    #   result = ScanResult.new("MyRule", rule_ptr, true, rule_source, scanned_data)
    def initialize(rule_name, rule_ptr, is_match = true, rule_source = nil, scanned_data = nil)
      @rule_name = rule_name
      @rule_ptr = rule_ptr
      @is_match = is_match
      @rule_source = rule_source
      @scanned_data = scanned_data
      @rule_meta = {}
      @rule_strings = {}
      @pattern_matches = {}

      # For now, parse metadata and strings from source as a temporary solution
      if @rule_source
        parse_metadata_from_source
        parse_strings_from_source
      end

      # Extract detailed pattern match information using YARA-X API
      if @rule_ptr && !@rule_ptr.null?
        extract_pattern_matches
      end
    end

    # Public: Check if this result represents a rule match.
    #
    # Examples
    #
    #   if result.match?
    #     puts "Rule #{result.rule_name} matched!"
    #   end
    #
    # Returns a Boolean indicating whether the rule matched.
    def match?
      @is_match
    end

    # Public: Get all matches for a specific pattern by name.
    #
    # This method returns an array of PatternMatch objects for the specified
    # pattern identifier, or an empty array if the pattern didn't match or
    # doesn't exist.
    #
    # pattern_name - A String or Symbol identifying the pattern (e.g., "$text1")
    #
    # Examples
    #
    #   # Get matches for a specific pattern
    #   matches = result.matches_for_pattern("$suspicious_string")
    #   matches.each { |m| puts "Found at offset #{m.offset}" }
    #
    # Returns an Array of PatternMatch objects.
    def matches_for_pattern(pattern_name)
      key = pattern_name.is_a?(Symbol) ? pattern_name : pattern_name.to_sym
      @pattern_matches[key] || []
    end

    # Public: Get the total number of pattern matches across all patterns.
    #
    # This convenience method counts the total matches across all patterns
    # that triggered for this rule.
    #
    # Examples
    #
    #   puts "Rule matched with #{result.total_matches} pattern matches"
    #
    # Returns an Integer count of total matches.
    def total_matches
      @pattern_matches.values.map(&:size).sum
    end

    # Public: Get all match locations as a flattened array.
    #
    # This method returns all pattern matches across all patterns as a single
    # array, sorted by offset. Useful for getting an overview of all match
    # locations in the data.
    #
    # Examples
    #
    #   # Get all matches sorted by location
    #   all_matches = result.all_matches.sort_by(&:offset)
    #   all_matches.each { |m| puts "Match at #{m.offset}" }
    #
    # Returns an Array of PatternMatch objects sorted by offset.
    def all_matches
      @pattern_matches.values.flatten.sort_by(&:offset)
    end

    # Public: Check if a specific pattern had any matches.
    #
    # This convenience method checks whether the specified pattern identifier
    # had any matches during scanning.
    #
    # pattern_name - A String or Symbol identifying the pattern
    #
    # Examples
    #
    #   if result.pattern_matched?("$malware_signature")
    #     puts "Malware signature detected!"
    #   end
    #
    # Returns a Boolean indicating whether the pattern matched.
    def pattern_matched?(pattern_name)
      matches_for_pattern(pattern_name).any?
    end

    # Internal: Extract detailed pattern match information using YARA-X API.
    #
    # This method uses the YARA-X C API to iterate through all patterns defined
    # in the matched rule and collect detailed match information including exact
    # offsets and lengths for each match.
    #
    # This replaces the need to parse pattern information from rule source code
    # and provides precise forensic data about what matched and where.
    #
    # Returns nothing (modifies @pattern_matches hash).
    def extract_pattern_matches
      return unless @rule_ptr && !@rule_ptr.null?

      # Collect pattern match data by iterating through patterns
      pattern_callback = proc do |pattern_ptr, user_data|
        next if pattern_ptr.nil? || pattern_ptr.null?

        # Get pattern identifier
        ident_ptr = ::FFI::MemoryPointer.new(:pointer)
        len_ptr = ::FFI::MemoryPointer.new(:size_t)

        result = Yara::FFI.yrx_pattern_identifier(pattern_ptr, ident_ptr, len_ptr)
        next unless result == Yara::FFI::YRX_SUCCESS

        identifier_ptr = ident_ptr.get_pointer(0)
        next if identifier_ptr.nil? || identifier_ptr.null?

        identifier_len = len_ptr.get_ulong(0)
        pattern_name = identifier_ptr.read_string(identifier_len).to_sym

        # Initialize match array for this pattern
        @pattern_matches[pattern_name] ||= []

        # Iterate through matches for this pattern
        match_callback = proc do |match_ptr, match_user_data|
          next if match_ptr.nil? || match_ptr.null?

          # Extract match details using FFI struct
          match = Yara::FFI::YRX_MATCH.new(match_ptr)
          pattern_match = PatternMatch.new(match[:offset], match[:length])
          @pattern_matches[pattern_name] << pattern_match
        end

        # Iterate through all matches for this pattern
        Yara::FFI.yrx_pattern_iter_matches(pattern_ptr, match_callback, nil)
      end

      # Iterate through all patterns in the rule
      Yara::FFI.yrx_rule_iter_patterns(@rule_ptr, pattern_callback, nil)
    end

    # Internal: Parse metadata from the original rule source code.
    #
    # This method uses regular expressions to extract key-value pairs from
    # the rule's meta section. It handles string, boolean, and numeric values
    # with basic type conversion. This is a temporary implementation until
    # YARA-X provides direct API access to rule metadata.
    #
    # Examples
    #
    #   # Given rule source with:
    #   # meta:
    #   #   author = "security_team"
    #   #   version = 1
    #   #   active = true
    #
    #   result.rule_meta[:author]  # => "security_team"
    #   result.rule_meta[:version] # => 1
    #   result.rule_meta[:active]  # => true
    #
    # Returns nothing (modifies @rule_meta hash).
    def parse_metadata_from_source
      return unless @rule_source

      # Extract metadata section more carefully
      if @rule_source =~ /meta:\s*(.*?)(?:strings:|condition:)/m
        meta_section = $1.strip

        # Parse each line in the meta section
        meta_section.split("\n").each do |line|
          line = line.strip
          next if line.empty?

          if line =~ /^(\w+)\s*=\s*(.+)$/
            key, value = $1, $2
            parsed_value = parse_meta_value(value.strip)
            @rule_meta[key.to_sym] = parsed_value
          end
        end
      end
    end

    # Internal: Parse string patterns from the original rule source code.
    #
    # This method uses regular expressions to extract pattern definitions from
    # the rule's strings section. It captures both the pattern variable names
    # (like $string1) and their values, cleaning up quotes and regex delimiters.
    # This is a temporary implementation until YARA-X provides direct API access.
    #
    # Examples
    #
    #   # Given rule source with:
    #   # strings:
    #   #   $text = "hello world"
    #   #   $regex = /pattern[0-9]+/
    #   #   $hex = { 41 42 43 }
    #
    #   result.rule_strings[:$text]  # => "hello world"
    #   result.rule_strings[:$regex] # => "pattern[0-9]+"
    #   result.rule_strings[:$hex]   # => "{ 41 42 43 }"
    #
    # Returns nothing (modifies @rule_strings hash).
    def parse_strings_from_source
      return unless @rule_source

      # Extract strings section more carefully
      if @rule_source =~ /strings:\s*(.*?)(?:condition:)/m
        strings_section = $1.strip

        # Parse each line in the strings section
        strings_section.split("\n").each do |line|
          line = line.strip
          next if line.empty?

          if line =~ /^(\$\w+)\s*=\s*(.+)$/
            name, pattern = $1, $2
            # Clean up the pattern (remove quotes, regex delimiters)
            cleaned_pattern = pattern.strip.gsub(/^["\/]|["\/]$/, '')
            @rule_strings[name.to_sym] = cleaned_pattern
          end
        end
      end
    end

    # Internal: Parse and convert metadata values to appropriate Ruby types.
    #
    # This method handles basic type conversion for metadata values extracted
    # from rule source code. It recognizes quoted strings, boolean literals,
    # and numeric values, converting them to appropriate Ruby types.
    #
    # value - A String containing the raw metadata value from rule source
    #
    # Examples
    #
    #   parse_meta_value('"hello"')  # => "hello"
    #   parse_meta_value('true')     # => true
    #   parse_meta_value('42')       # => 42
    #   parse_meta_value('other')    # => "other"
    #
    # Returns the parsed value in the appropriate Ruby type.
    def parse_meta_value(value)
      case value
      when /^".*"$/
        value[1...-1] # Remove quotes
      when /^true$/i
        true
      when /^false$/i
        false
      when /^\d+$/
        value.to_i
      else
        value
      end
    end
  end
end
