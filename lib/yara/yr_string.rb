module Yara
  class YrString < FFI::Struct
    layout :identifier, :string
  end
end
