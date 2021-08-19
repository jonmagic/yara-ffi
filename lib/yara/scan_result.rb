module Yara
  class ScanResult
    RULE_MATCHING     = 1
    RULE_NOT_MATCHING = 2
    SCAN_FINISHED     = 3

    RULE_IDENTIFIER = 1

    attr_reader :callback_type, :rule

    def initialize(callback_type, rule_ptr)
      @callback_type = callback_type
      @rule = YrRule.new(rule_ptr)
    end

    def rule_name
      @rule.values[RULE_IDENTIFIER]
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
  end
end
