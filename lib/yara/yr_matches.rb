module Yara
  class YrMatches < FFI::Struct
    layout \
      :head, :pointer,
      :tail, :pointer,
      :count, :int32_t
  end
end
