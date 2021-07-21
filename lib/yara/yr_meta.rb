module Yara
  class YrMeta < FFI::Struct
    layout :identifier, :pointer
    layout :type, :int32
  end
end
