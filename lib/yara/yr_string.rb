module Yara
  class YrString < FFI::Struct
    layout :identifier, :pointer
  end
end
