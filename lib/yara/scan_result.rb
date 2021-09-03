module Yara
  class ScanResult
    RULE_MATCHING     = 1
    RULE_NOT_MATCHING = 2

    META_FLAGS_LAST_IN_RULE = 1

    META_TYPE_INTEGER = 1
    META_TYPE_STRING  = 2
    META_TYPE_BOOLEAN = 3

    STRING_FLAGS_LAST_IN_RULE = 0

    STRING_LENGTH = 4
    STRING_POINTER = 5

    attr_reader :callback_type, :context, :rule
    attr_reader :callback_type, :rule

    def initialize(context_ptr, callback_type, rule_ptr)
      @callback_type = callback_type
      @rule = YrRule.new(rule_ptr)
      @context = YrScanContext.new(context_ptr)
      @rule_meta = extract_rule_meta
      @rule_strings = extract_rule_strings
    end

    attr_reader :rule_meta, :rule_strings

    def rule_name
      @rule[:identifier]
    end

    def scan_complete?
      callback_type == SCAN_FINISHED
    end

    def rule_outcome?
      [RULE_MATCHING, RULE_NOT_MATCHING].include?(callback_type)
    end

    def match?
      callback_type == RULE_MATCHING
    end

    private

    def extract_rule_meta
      metas = {}
      reading_metas = true
      meta_index = 0
      meta_pointer = @rule[:metas]
      while reading_metas do
        meta = YrMeta.new(meta_pointer + meta_index * YrMeta.size)
        metas.merge!(meta_as_hash(meta))
        flags = meta.values.last
        if flags == META_FLAGS_LAST_IN_RULE
          reading_metas = false
        else
          meta_index += 1
        end
      end
      metas
    end

    def extract_rule_strings
      strings = {}
      reading_strings = true
      string_index = 0
      string_pointer = @rule[:strings]
      while reading_strings do
        string = YrString.new(string_pointer + string_index * YrString.size)
        string_length = string.values[STRING_LENGTH]
        flags = string.values.first
        if flags == STRING_FLAGS_LAST_IN_RULE
          reading_strings = false
        else
          strings.merge!(string_as_hash(string)) unless string_length == 0
          string_index += 1
        end
      end
      strings
    end

    def meta_as_hash(meta)
      name, string_value, int_value, type, _flags = meta.values
      value = meta_value(string_value, int_value, type)
      { name.to_sym => value }
    end

    def string_as_hash(yr_string)
      string_pointer = yr_string.values[STRING_POINTER]
      string_identifier = yr_string.values.last
      { string_identifier.to_sym => string_pointer.read_string }
    end

    def meta_value(string_value, int_value, type)
      if type == META_TYPE_INTEGER
        int_value
      elsif type == META_TYPE_BOOLEAN
        int_value == 1
      else
        string_value
      end
    end
  end
end
