module Yara
  # Public: Wrapper around the YARA-X YRX_COMPILER API.
  #
  # This class allows adding multiple sources, defining globals before
  # compilation, and building a YRX_RULES object that can be used by
  # {Yara::Scanner}.
  class Compiler
    class CompileError < StandardError; end

    def initialize(flags = 0)
      @compiler_ptr_holder = ::FFI::MemoryPointer.new(:pointer)
      result = Yara::FFI.yrx_compiler_create(flags, @compiler_ptr_holder)
      if result != Yara::FFI.yrx_last_error && result != Yara::FFI::YRX_SUCCESS
        # Defensive: use yrx_last_error for message but prefer success check
      end

      if result != Yara::FFI::YRX_SUCCESS
        raise CompileError, "Failed to create compiler: #{Yara::FFI.yrx_last_error}"
      end
      @compiler = @compiler_ptr_holder.get_pointer(0)
    end

    def add_source(src, origin = nil)
      if origin
        result = Yara::FFI.yrx_compiler_add_source_with_origin(@compiler, src, origin)
      else
        result = Yara::FFI.yrx_compiler_add_source(@compiler, src)
      end

      if result != Yara::FFI::YRX_SUCCESS
        raise CompileError, "Failed to add source: #{Yara::FFI.yrx_last_error}"
      end
      nil
    end

    def define_global_str(ident, value)
      result = Yara::FFI.yrx_compiler_define_global_str(@compiler, ident, value)
      if result != Yara::FFI::YRX_SUCCESS
        raise CompileError, "Failed to define global str #{ident}: #{Yara::FFI.yrx_last_error}"
      end
      nil
    end

    def define_global_bool(ident, value)
      result = Yara::FFI.yrx_compiler_define_global_bool(@compiler, ident, !!value)
      if result != Yara::FFI::YRX_SUCCESS
        raise CompileError, "Failed to define global bool #{ident}: #{Yara::FFI.yrx_last_error}"
      end
      nil
    end

    def define_global_int(ident, value)
      result = Yara::FFI.yrx_compiler_define_global_int(@compiler, ident, value)
      if result != Yara::FFI::YRX_SUCCESS
        raise CompileError, "Failed to define global int #{ident}: #{Yara::FFI.yrx_last_error}"
      end
      nil
    end

    def define_global_float(ident, value)
      result = Yara::FFI.yrx_compiler_define_global_float(@compiler, ident, value)
      if result != Yara::FFI::YRX_SUCCESS
        raise CompileError, "Failed to define global float #{ident}: #{Yara::FFI.yrx_last_error}"
      end
      nil
    end

    # Build and return a pointer to YRX_RULES. The caller is responsible for
    # calling yrx_rules_destroy on the returned pointer when finished.
    def build
      rules_ptr = Yara::FFI.yrx_compiler_build(@compiler)
      if rules_ptr.nil? || rules_ptr.null?
        raise CompileError, "Failed to build rules: #{Yara::FFI.yrx_last_error}"
      end
      rules_ptr
    end

    # Return compilation errors as a parsed JSON object (Array of error objects).
    # This uses yrx_compiler_errors_json which returns a YRX_BUFFER containing
    # the JSON serialization. The buffer is destroyed after being converted.
    def errors_json
      buf_ptr_holder = ::FFI::MemoryPointer.new(:pointer)
      result = Yara::FFI.yrx_compiler_errors_json(@compiler, buf_ptr_holder)
      if result != Yara::FFI::YRX_SUCCESS
        raise CompileError, "Failed to get errors JSON: #{Yara::FFI.yrx_last_error}"
      end

      buf_ptr = buf_ptr_holder.get_pointer(0)
      buffer = Yara::FFI::YRX_BUFFER.new(buf_ptr)
      data_ptr = buffer[:data]
      length = buffer[:length]
      json_str = data_ptr.read_string_length(length)
      Yara::FFI.yrx_buffer_destroy(buf_ptr)

      JSON.parse(json_str)
    end

    # Return compilation warnings as parsed JSON (Array of warning objects).
    def warnings_json
      buf_ptr_holder = ::FFI::MemoryPointer.new(:pointer)
      result = Yara::FFI.yrx_compiler_warnings_json(@compiler, buf_ptr_holder)
      if result != Yara::FFI::YRX_SUCCESS
        raise CompileError, "Failed to get warnings JSON: #{Yara::FFI.yrx_last_error}"
      end

      buf_ptr = buf_ptr_holder.get_pointer(0)
      buffer = Yara::FFI::YRX_BUFFER.new(buf_ptr)
      data_ptr = buffer[:data]
      length = buffer[:length]
      json_str = data_ptr.read_string_length(length)
      Yara::FFI.yrx_buffer_destroy(buf_ptr)

      JSON.parse(json_str)
    end

    def destroy
      Yara::FFI.yrx_compiler_destroy(@compiler) if @compiler
      @compiler = nil
    end

    # Ensure resources are cleaned up.
    def finalize
      destroy
    end
  end
end
