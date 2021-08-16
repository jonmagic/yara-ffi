module Yara
  class YrRule < FFI::Struct
    layout \
      :flags, :int32_t,
      :identifier, :string,
      :tags, :string,
      :metas, YrMeta.ptr,
      :strings, YrString.ptr,
      :ns, YrNamespace.ptr
  end
end
