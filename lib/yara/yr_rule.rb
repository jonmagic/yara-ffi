module Yara
  class YrRule < FFI::Struct
    layout :identifier, :pointer
    layout :tags, :pointer
    layout :metas, :pointer
    layout :strings, :pointer
    layout :ns, :pointer
  end
end
