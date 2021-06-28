module Yara
  class YrRule < FFI::Struct
    layout :identifier, :pointer
    layout :type, :int32
  end
end
