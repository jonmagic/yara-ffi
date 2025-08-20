## [Unreleased]

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
