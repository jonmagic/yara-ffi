module Yara
  class ScanResult
    attr_reader :rule_name, :rule_ptr

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

    attr_reader :rule_meta, :rule_strings

    def match?
      @is_match
    end

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
