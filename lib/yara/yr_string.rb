module Yara
  class YrString < FFI::Struct
    layout \
      :flags, :uint32_t,
      :idx, :uint32_t,
      :fixed_offset, :uint64_t,
      :rule_idx, :uint32_t,
      :length, :int32_t,
      :string, :pointer,
      :chained_to, :pointer,
      :chain_gap_min, :int32_t,
      :chain_gap_max, :int32_t,
      :identifier, :string
  end
end
