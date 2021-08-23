module Yara
  class YrMeta < FFI::Struct
    layout \
      :identifier, :string,
      :string, :string,
      :integer, :int64_t,
      :type, :int32_t,
      :flags, :int32_t
  end
end
