# Development Guide

This guide covers setting up the development environment and working on the yara-ffi gem.

## Requirements

- Docker (for containerized development environment)

## Quick Start

After checking out the repo, run the bootstrap script to set up the development environment:

```bash
script/bootstrap
```

This will build a Docker image with all the necessary dependencies, including the YARA-X C API library.

## Development Scripts

The project includes several convenience scripts in the `script/` directory:

- `script/bootstrap` - Sets up the development environment (builds Docker image)
- `script/test` - Runs the test suite in the Docker container

## Running Tests

To run the full test suite:

```bash
script/test
```

This runs `bundle exec rake` inside the Docker container with all dependencies properly configured.

You can also run tests manually inside the container:

```bash
docker run -it --mount type=bind,src="$(pwd)",dst=/app yara-ffi bundle exec rake
```

Or run specific test files:

```bash
docker run -it --mount type=bind,src="$(pwd)",dst=/app yara-ffi bundle exec ruby -Itest test/scanner_test.rb
```

Alternatively, you can use rake to run specific tests:

```bash
docker run -it --mount type=bind,src="$(pwd)",dst=/app yara-ffi bundle exec rake test TEST=test/scanner_test.rb
```

## Interactive Development

For an interactive development session, you can start a console in the container:

```bash
docker run -it --mount type=bind,src="$(pwd)",dst=/app yara-ffi bin/console
```

This gives you an IRB session with the gem loaded for experimentation.

## Development Environment Details

The development environment uses Docker to provide a consistent setup with:

- Ruby 3.3 (latest stable)
- YARA-X C API library v1.5.0 built from source
- All necessary system dependencies
- Bundler with locked gem versions

### Docker Image

The `Dockerfile` sets up:

1. Base Ruby 3.3 image
2. System dependencies (curl, git, unzip)
3. Rust toolchain and cargo-c for building YARA-X
4. YARA-X C API library compiled and installed
5. Ruby gem dependencies via Bundler

### Manual Setup (without Docker)

If you prefer not to use Docker, you'll need to manually install:

1. Ruby 3.0+
2. YARA-X C API library (see [Installation section in README](README.md#installing-yara-x))
3. System dependencies for building native gems

Then run:

```bash
bundle install
rake test
```

## Code Structure

The gem is organized as follows:

- `lib/yara.rb` - Main entry point and convenience methods
- `lib/yara/ffi.rb` - FFI bindings to YARA-X C API
- `lib/yara/scanner.rb` - Scanner class for rule compilation and scanning
- `lib/yara/scan_result.rb` - Individual scan result wrapper
- `lib/yara/scan_results.rb` - Collection of scan results
- `lib/yara/version.rb` - Gem version constant

## Testing

Tests are located in the `test/` directory:

- `test/yara_test.rb` - Tests for main module convenience methods
- `test/scanner_test.rb` - Tests for Scanner class functionality
- `test/test_helper.rb` - Shared test setup and utilities

The test suite uses Minitest and includes tests for:

- Rule compilation and validation
- Data scanning with various rule types
- Memory management and resource cleanup
- Error handling and edge cases

## Release Process

To release a new version of the gem:

1. Update the version number in `lib/yara/version.rb`
2. Update the `CHANGELOG.md` with release notes
3. Commit the changes
4. Create and push a git tag:
   ```bash
   git tag v<version>
   git push origin v<version>
   ```
5. Build and push the gem:
   ```bash
   gem build yara-ffi.gemspec
   gem push yara-ffi-<version>.gem
   ```

## Contributing Guidelines

1. Fork the repository
2. Create a feature branch (`git checkout -b my-new-feature`)
3. Make your changes with appropriate tests
4. Run the test suite (`script/test`) to ensure all tests pass
5. Commit your changes (`git commit -am 'Add some feature'`)
6. Push to the branch (`git push origin my-new-feature`)
7. Create a Pull Request

Please ensure your code follows the existing style and includes tests for new functionality.

## Debugging

For debugging FFI-related issues:

1. Enable FFI debugging by setting the `RUBY_FFI_DEBUG` environment variable
2. Use `puts` statements or `binding.pry` (if pry is available) for Ruby debugging
3. Check YARA-X C API documentation for expected behavior
4. Verify memory management - ensure all resources are properly freed

## Common Issues

### YARA-X Library Not Found

If you see errors about missing YARA-X libraries, ensure:

1. The YARA-X C API library is properly installed
2. The library path is in your system's library search path
3. You're using the correct version (v1.5.0 is tested)

### Docker Build Issues

If Docker builds fail:

1. Ensure you have sufficient disk space
2. Try rebuilding without cache: `docker build --no-cache . -t yara-ffi`
3. Check internet connectivity for downloading dependencies

### Test Failures

If tests fail:

1. Ensure all dependencies are properly installed
2. Check that YARA-X C API library is available
3. Verify Ruby version compatibility (3.0+ required)
4. Run tests individually to isolate issues
