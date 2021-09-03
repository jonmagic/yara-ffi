module Yara
  class YrScanContext < FFI::Struct
    layout \
      :file_size, :uint64_t,
      :entry_point, :uint64_t,
      :flags, :int,
      :canary, :int,
      :timeout, :uint64_t,
      :user_data, :pointer,
      :callback, :pointer,
      :rules, :pointer,
      :last_error_string, :pointer,
      :iterator, :pointer,
      :objects_table, :pointer,
      :matches_notebook, :pointer,
      :stopwatch, :pointer,
      :re_fiber_pool, :pointer,
      :re_fast_exec_position_pool, :pointer,
      :rule_matches_flags, :pointer,
      :ns_unsatisfied_flags, :pointer,
      :strings_temp_disabled, :pointer,
      :matches, :pointer,
      :unconfirmed_matches, :pointer,
      :profiling_info, :pointer
  end
end
