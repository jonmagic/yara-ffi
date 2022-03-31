module Yara
  class YrMeta < FFI::Struct
    layout \
      :identifier, :string,
      :string, :string,
      :integer, :ulong_long,
      :type, :int,
      :flags, :int
  end
end
