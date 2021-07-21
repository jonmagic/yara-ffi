module Yara
  class YrRule < FFI::Struct
    layout :identifier, :pointer
    layout :tags, :pointer
    layout :metas, YrMeta.ptr
    layout :strings, YrString.ptr
    layout :ns, YrNamespace.ptr
  end
end
