module Yara
  class YrNamespace < FFI::Struct
    layout :name, :pointer
  end
end
