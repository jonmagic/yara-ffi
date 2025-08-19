## [Unreleased]

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
