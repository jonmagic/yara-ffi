module Yara
  class YrMeta < FFI::Struct
    layout \
      :identifier, :string,
      :type, :int32_t
  end
end
