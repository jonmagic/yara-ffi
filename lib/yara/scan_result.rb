module Yara
  # Public: Represents a single rule match result from YARA scanning.
  #
  # A ScanResult contains information about a YARA rule that matched during
  # scanning, including the rule name, metadata, and string patterns. This
  # class provides access to rule information extracted from both the YARA-X
  # API and parsed rule source code.
  #
  # Currently, metadata and string parsing is implemented by parsing the
  # original rule source code using regular expressions. This is a temporary
  # solution until YARA-X provides more complete API access to rule internals.
  #
  # Examples
  #
  #   # Typically created by Scanner during scanning
  #   scanner.scan(data) do |result|
  #     puts "Matched rule: #{result.rule_name}"
  #     puts "Author: #{result.rule_meta[:author]}"
  #     puts "Patterns: #{result.rule_strings.keys}"
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

    # Public: Initialize a new ScanResult.
    #
    # This constructor is typically called internally by Scanner when a rule
    # matches during scanning. It extracts available information from both
    # the YARA-X API and the original rule source code.
    #
    # rule_name   - A String containing the rule identifier/name
    # rule_ptr    - An FFI Pointer to the YRX_RULE structure
    # is_match    - A Boolean indicating if this represents a match (default true)
    # rule_source - An optional String containing the original rule source for parsing
    #
    # Examples
    #
    #   # Typically created internally by Scanner
    #   result = ScanResult.new("MyRule", rule_ptr, true, rule_source)
    def initialize(rule_name, rule_ptr, is_match = true, rule_source = nil)
      @rule_name = rule_name
      @rule_ptr = rule_ptr
      @is_match = is_match
      @rule_source = rule_source
      @rule_meta = {}
      @rule_strings = {}

      # For now, parse metadata and strings from source as a temporary solution
      if @rule_source
        parse_metadata_from_source
        parse_strings_from_source
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
