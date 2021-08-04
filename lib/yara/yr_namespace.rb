module Yara
  class YrNamespace < FFI::Struct
    layout :name, :string
  end
end
