module Yara
  class YrMatch < FFI::Struct
    layout \
      :base, :int64_t,
      :offset, :int64_t,
      :match_length, :int32_t,
      :data_length, :int32_t,
      :data, :pointer,
      :prev, :pointer,
      :next, :pointer,
      :chain_length, :int32_t,
      :is_private, :bool
  end
end
