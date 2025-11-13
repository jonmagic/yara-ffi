## [Unreleased]

## [4.2.0] - 2025-11-13

- **NEW**: Added rule iteration API for inspecting compiled rules without scanning
  - `Scanner#each_rule` - Iterate through all compiled rules (returns Enumerator)
  - `Yara::Rule` class for accessing rule properties
  - `Rule#identifier` - Get rule name
  - `Rule#namespace` - Get rule namespace
  - `Rule#metadata` - Access rule metadata as hash
  - `Rule#tags` - Get rule tags as array
  - Enables building rule catalogs and introspection without scanning data
  - Works with compiled rules from `Scanner`, `Compiler`, or deserialized rules
- **IMPROVED**: Enhanced FFI struct handling for better memory safety with unions

## [4.1.1] - 2025-08-20

- **FIXED**: Fixed crash when `Yara.test` or `Yara.scan` receive `nil` as the test string parameter ([#15](https://github.com/jonmagic/yara-ffi/issues/15))
  - `nil` values are now treated as empty strings instead of causing `NoMethodError`
  - Both `Yara.test(rule, nil)` and `Yara.scan(rule, nil)` now return empty `ScanResults` objects

## [4.1.0] - 2025-08-20

- **NEW**: Added advanced `Yara::Compiler` API for complex rule compilation scenarios
  - `Compiler.new` - Create a new compiler instance
  - `Compiler#define_global_*` methods for setting globals before compilation
  - `Compiler#add_source` for adding rules from multiple sources
  - `Compiler#build` and `Compiler#build_serialized` for creating compiled rules
  - `Compiler#errors_json` and `Compiler#warnings_json` for detailed diagnostics
- **NEW**: Added rule serialization and deserialization support
  - `Scanner.from_serialized` - Create scanner from serialized rules
  - `Scanner.from_rules` - Create scanner from pre-compiled rules
  - Enables compile-once, use-many-times pattern for production deployments
- **NEW**: Enhanced pattern matching analysis with `Yara::PatternMatch`
  - Detailed pattern match information with offsets and lengths
  - `PatternMatch#offset`, `PatternMatch#length`, `PatternMatch#matched_data`
  - `ScanResult#matches_for_pattern` - Get matches for specific patterns
  - `ScanResult#pattern_matched?` - Check if specific pattern matched
  - `ScanResult#total_matches` and `ScanResult#all_matches` for match analysis
- **NEW**: Added comprehensive metadata and tag support
  - Type-safe metadata accessors: `metadata_string`, `metadata_int`, `metadata_bool`
  - `ScanResult#tags` - Access rule tags as array
  - `ScanResult#has_tag?` - Check for specific tags
  - `ScanResult#qualified_name` - Get namespaced rule name
- **NEW**: Added global variable support for scanners
  - `Scanner#set_global_str`, `Scanner#set_global_int`, `Scanner#set_global_bool`, `Scanner#set_global_float`
  - `Scanner#set_globals` - Bulk setting with error handling options
  - Enable dynamic rule behavior based on runtime variables
- **NEW**: Added scanner timeout configuration via `Scanner#set_timeout`
- **IMPROVED**: Enhanced documentation with comprehensive usage examples in `USAGE.md`
- **IMPROVED**: Updated development documentation and AI coding instructions

## [4.0.0] - 2025-08-19

- **BREAKING**: Migrated from legacy libyara FFI bindings to YARA-X C API (`libyara_x_capi.so`) ([#24](https://github.com/jonmagic/yara-ffi/pull/24))
  - Removed all legacy FFI struct definitions (`YrRule`, `YrMeta`, `YrString`, etc.)
  - Replaced incremental rule compilation with single-step compilation via `yrx_compile`
  - Eliminated dependency on `Yara.start` and `Yara.stop` lifecycle methods
- **BREAKING**: Changed `Scanner#call` to `Scanner#scan` method ([#24](https://github.com/jonmagic/yara-ffi/pull/24))
- **BREAKING**: Require Ruby >= 3.0.0 ([#24](https://github.com/jonmagic/yara-ffi/pull/24))
- **BREAKING**: Remove `ScanResult` return for non-matching scans ([#24](https://github.com/jonmagic/yara-ffi/pull/24))
- Added `Yara::ScanResults` enumerable collection for managing scan results ([#24](https://github.com/jonmagic/yara-ffi/pull/24))
- Added `Scanner.open` for block-based resource management ([#24](https://github.com/jonmagic/yara-ffi/pull/24))
- Added streaming scan API support with block yielding ([#24](https://github.com/jonmagic/yara-ffi/pull/24))
- Modernized CI workflow with Ruby 3.0-3.3 matrix testing and YARA-X build support ([#24](https://github.com/jonmagic/yara-ffi/pull/24))
- Added comprehensive development documentation in `DEVELOPMENT.md` ([#24](https://github.com/jonmagic/yara-ffi/pull/24))
- Updated Docker environment to Ruby 3.3 with YARA-X v1.5.0 ([#24](https://github.com/jonmagic/yara-ffi/pull/24))
- Improved error handling for compilation and scanning with better exception handling
- Preserved backward compatibility in `ScanResult` interface via fallback parsing
- Removed obsolete helper files: `user_data.rb`, `yr_meta.rb`, `yr_string.rb`, `yr_namespace.rb`, `yr_rule.rb`

## [3.1.0] - 2022-04-18

- Minor documentation fix for `Scanner::call` return value ([#20](https://github.com/jonmagic/yara-ffi/pull/20))
- Fix FFI type compatibility issues on ARM64 Linux by converting integer types ([#21](https://github.com/jonmagic/yara-ffi/pull/21))

## [3.0.0] - 2021-10-21

- **BREAKING**: Introduced new `Yara::Scanner` API for better memory management and control ([#17](https://github.com/jonmagic/yara-ffi/pull/17))
- Added proper memory cleanup with `yr_compiler_destroy` and `yr_rules_destroy` calls
- Moved core functionality to `Yara::Scanner` class

## [2.1.1] - 2021-08-31

- Fix memory leak by calling destroy methods ([#11](https://github.com/jonmagic/yara-ffi/pull/11))

## [2.1.0] - 2021-08-30

- Use struct hash access and `Struct.ptr` where possible ([#14](https://github.com/jonmagic/yara-ffi/pull/14))
- Improved struct member access and performance optimizations

## [2.0.1] - 2021-08-30

- Bug fixes and improvements

## [2.0.0] - 2021-08-24

- **BREAKING**: Changed interface to support rule metas ([#4](https://github.com/jonmagic/yara-ffi/pull/4))
- `Yara.test` now returns `Yara::ScanResult` objects instead of rule names
- Added support for accessing rule metadata as hash of name => value
- Return rule metas in scan results

## [1.0.0] - 2021-08-16

- Wire up basic Yara functionality ([#3](https://github.com/jonmagic/yara-ffi/pull/3))
- Added `Yara.test(rules_string, string_to_scan)` functionality
- Initial FFI bindings to libyara

## [0.1.0] - 2021-03-11

- Initial release with project structure ([#1](https://github.com/jonmagic/yara-ffi/pull/1), [#2](https://github.com/jonmagic/yara-ffi/pull/2))
- Set up GitHub Actions CI
- Configured RuboCop
