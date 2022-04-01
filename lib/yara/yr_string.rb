module Yara
  class YrString < FFI::Struct
    layout \
      :flags, :uint,
      :idx, :uint,
      :fixed_offset, :ulong_long,
      :rule_idx, :uint,
      :length, :uint,
      :string, :pointer,
      :chained_to, :pointer,
      :chain_gap_min, :uint,
      :chain_gap_max, :uint,
      :identifier, :string
  end
end
