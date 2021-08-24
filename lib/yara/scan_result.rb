module Yara
  class ScanResult
    RULE_MATCHING     = 1
    RULE_NOT_MATCHING = 2

    META_FLAGS_LAST_IN_RULE = 1

    META_TYPE_INTEGER = 1
    META_TYPE_STRING  = 2
    META_TYPE_BOOLEAN = 3

    RULE_IDENTIFIER  = 1
    METAS_IDENTIFIER = 3

    attr_reader :callback_type, :rule

    def initialize(callback_type, rule_ptr)
      @callback_type = callback_type
      @rule = YrRule.new(rule_ptr)
    end

    def rule_name
      @rule.values[RULE_IDENTIFIER]
    end

    def rule_meta
      metas = {}
      reading_metas = true
      meta_index = 0
      meta_pointer = @rule.values[METAS_IDENTIFIER]
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

    def meta_as_hash(meta)
      name, string_value, int_value, type, _flags = meta.values
      value = meta_value(string_value, int_value, type)
      { name.to_sym => value }
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
