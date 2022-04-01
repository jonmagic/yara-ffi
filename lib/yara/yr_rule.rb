module Yara
  class YrRule < FFI::Struct
    layout \
      :flags, :int,
      :identifier, :string,
      :tags, :string,
      :metas, :pointer,
      :strings, :pointer,
      :ns, YrNamespace.ptr
  end
end
