# frozen_string_literal: true

module Yara
  # Public: Represents a YARA rule from compiled rules.
  #
  # A Rule provides access to a YARA rule's metadata, tags, and patterns
  # without needing to scan any data. This is useful for inspecting compiled
  # rules, extracting metadata, and understanding rule structure.
  #
  # Examples
  #
  #   # Typically created by Scanner#each_rule
  #   scanner.each_rule do |rule|
  #     puts "Rule: #{rule.identifier}"
  #     puts "Namespace: #{rule.namespace}"
  #     puts "Tags: #{rule.tags.join(', ')}"
  #     rule.metadata.each { |k, v| puts "  #{k}: #{v}" }
  #   end
  class Rule
    # Public: The identifier (name) of the rule.
    attr_reader :identifier

    # Public: The namespace of the rule.
    attr_reader :namespace

    # Public: FFI pointer to the underlying YRX_RULE structure.
    attr_reader :rule_ptr

    # Public: Initialize a new Rule from a YRX_RULE pointer.
    #
    # This constructor extracts the rule identifier, namespace, metadata,
    # and tags using the YARA-X C API.
    #
    # rule_ptr - An FFI Pointer to the YRX_RULE structure
    #
    # Examples
    #
    #   # Typically created internally by Scanner#each_rule
    #   rule = Rule.new(rule_ptr)
    def initialize(rule_ptr)
      @rule_ptr = rule_ptr
      @identifier = extract_identifier
      @namespace = extract_namespace
      @metadata_cache = nil
      @tags_cache = nil
    end

    # Public: Get the rule's metadata as a Hash.
    #
    # Metadata is extracted from the rule's meta section and includes
    # various types: strings, integers, floats, booleans, and bytes.
    #
    # Returns a Hash mapping metadata keys (Symbols) to their values.
    #
    # Examples
    #
    #   metadata = rule.metadata
    #   # => { author: "test", severity: 5, is_malware: true }
    def metadata
      @metadata_cache ||= extract_metadata
    end

    # Public: Get the rule's tags as an Array.
    #
    # Tags are labels used to categorize and organize rules, defined
    # after the rule name in the rule definition.
    #
    # Returns an Array of Strings containing the rule's tags.
    #
    # Examples
    #
    #   tags = rule.tags
    #   # => ["malware", "trojan"]
    def tags
      @tags_cache ||= extract_tags
    end

    # Public: Get a qualified name combining namespace and identifier.
    #
    # Returns a String in the format "namespace.identifier".
    #
    # Examples
    #
    #   rule.qualified_name
    #   # => "malware.trojan_detector"
    def qualified_name
      return identifier if namespace.nil? || namespace.empty?

      "#{namespace}.#{identifier}"
    end

    # Public: Check if the rule has a specific tag.
    #
    # tag - A String or Symbol representing the tag to check
    #
    # Returns true if the tag exists, false otherwise.
    #
    # Examples
    #
    #   rule.has_tag?("malware")
    #   # => true
    def has_tag?(tag)
      tags.include?(tag.to_s)
    end

    # Public: Get a metadata value by key with type checking.
    #
    # key - A Symbol or String representing the metadata key
    #
    # Returns the metadata value if found, nil otherwise.
    #
    # Examples
    #
    #   rule.metadata_value(:author)
    #   # => "test_author"
    def metadata_value(key)
      metadata[key.to_sym]
    end

    # Public: Get a String metadata value with type validation.
    #
    # key - A Symbol or String representing the metadata key
    #
    # Returns the String value if found and is a String, nil otherwise.
    #
    # Examples
    #
    #   rule.metadata_string(:author)
    #   # => "test_author"
    def metadata_string(key)
      value = metadata_value(key)
      value.is_a?(String) ? value : nil
    end

    # Public: Get an Integer metadata value with type validation.
    #
    # key - A Symbol or String representing the metadata key
    #
    # Returns the Integer value if found and is an Integer, nil otherwise.
    #
    # Examples
    #
    #   rule.metadata_int(:severity)
    #   # => 5
    def metadata_int(key)
      value = metadata_value(key)
      value.is_a?(Integer) ? value : nil
    end

    # Public: Get a Boolean metadata value with type validation.
    #
    # key - A Symbol or String representing the metadata key
    #
    # Returns the Boolean value if found and is a Boolean, nil otherwise.
    #
    # Examples
    #
    #   rule.metadata_bool(:is_malware)
    #   # => true
    def metadata_bool(key)
      value = metadata_value(key)
      [true, false].include?(value) ? value : nil
    end

    # Public: Get a Float metadata value with type validation.
    #
    # key - A Symbol or String representing the metadata key
    #
    # Returns the Float value if found and is a Float, nil otherwise.
    #
    # Examples
    #
    #   rule.metadata_float(:confidence)
    #   # => 0.95
    def metadata_float(key)
      value = metadata_value(key)
      value.is_a?(Float) ? value : nil
    end

    # Internal: Extract the rule identifier using YARA-X API.
    #
    # Returns a String containing the rule name.
    def extract_identifier
      ident_ptr = ::FFI::MemoryPointer.new(:pointer)
      len_ptr = ::FFI::MemoryPointer.new(:size_t)

      result = Yara::FFI.yrx_rule_identifier(@rule_ptr, ident_ptr, len_ptr)
      if result != Yara::FFI::YRX_SUCCESS
        raise "Failed to extract rule identifier: #{Yara::FFI.yrx_last_error}"
      end

      ident = ident_ptr.read_pointer
      length = len_ptr.read(:size_t)
      ident.read_bytes(length).force_encoding("UTF-8")
    end

    # Internal: Extract the rule namespace using YARA-X API.
    #
    # Returns a String containing the namespace, or nil if default namespace.
    def extract_namespace
      ns_ptr = ::FFI::MemoryPointer.new(:pointer)
      len_ptr = ::FFI::MemoryPointer.new(:size_t)

      result = Yara::FFI.yrx_rule_namespace(@rule_ptr, ns_ptr, len_ptr)
      if result != Yara::FFI::YRX_SUCCESS
        raise "Failed to extract rule namespace: #{Yara::FFI.yrx_last_error}"
      end

      ns = ns_ptr.read_pointer
      length = len_ptr.read(:size_t)
      namespace_str = ns.read_bytes(length).force_encoding("UTF-8")

      # Return nil for default namespace
      namespace_str.empty? ? nil : namespace_str
    end

    # Internal: Extract metadata from the rule using YARA-X API.
    #
    # Returns a Hash mapping metadata keys to their values.
    def extract_metadata
      metadata = {}

      metadata_callback = proc do |metadata_ptr, _user_data|
        begin
          # Read identifier (first field, pointer at offset 0)
          identifier_ptr = metadata_ptr.get_pointer(0)
          next if identifier_ptr.null?
          identifier = identifier_ptr.read_string.to_sym

          # Read value_type (int at offset 8, after the 8-byte pointer)
          value_type = metadata_ptr.get_int32(8)

          # The value union starts at offset 16 (pointer:8 + int:4 + padding:4)
          # This is due to struct alignment requirements
          value_offset = 16

          value = case value_type
          when Yara::FFI::YRX_METADATA_TYPE_I64
            metadata_ptr.get_int64(value_offset)
          when Yara::FFI::YRX_METADATA_TYPE_F64
            metadata_ptr.get_double(value_offset)
          when Yara::FFI::YRX_METADATA_TYPE_BOOLEAN
            metadata_ptr.get_uint8(value_offset) != 0
          when Yara::FFI::YRX_METADATA_TYPE_STRING
            str_ptr = metadata_ptr.get_pointer(value_offset)
            str_ptr.null? ? nil : str_ptr.read_string
          when Yara::FFI::YRX_METADATA_TYPE_BYTES
            length = metadata_ptr.get_size_t(value_offset)
            data_ptr = metadata_ptr.get_pointer(value_offset + 8)
            (data_ptr.null? || length == 0) ? nil : data_ptr.read_bytes(length)
          else
            nil
          end

          metadata[identifier] = value unless value.nil?
        rescue => e
          # Skip problematic metadata entries to ensure partial extraction works
        end
      end

      result = Yara::FFI.yrx_rule_iter_metadata(@rule_ptr, metadata_callback, nil)
      if result != Yara::FFI::YRX_SUCCESS
        raise "Failed to iterate rule metadata: #{Yara::FFI.yrx_last_error}"
      end

      metadata
    end

    # Internal: Extract tags from the rule using YARA-X API.
    #
    # Returns an Array of Strings containing the rule's tags.
    def extract_tags
      tags = []

      tag_callback = proc do |tag_ptr, _user_data|
        tags << tag_ptr.read_string unless tag_ptr.null?
      end

      result = Yara::FFI.yrx_rule_iter_tags(@rule_ptr, tag_callback, nil)
      if result != Yara::FFI::YRX_SUCCESS
        raise "Failed to iterate rule tags: #{Yara::FFI.yrx_last_error}"
      end

      tags
    end
  end
end
