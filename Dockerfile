
FROM ruby:3.3

RUN apt-get update -qq \
  && apt-get install -y curl git unzip

WORKDIR /app

COPY . ./
RUN gem install bundler:2.2.15 \
  && bundle install

# Install Rust and cargo-c for building YARA-X C API
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
  && . $HOME/.cargo/env \
  && cargo install cargo-c

# Build and install YARA-X C API library
RUN . $HOME/.cargo/env \
  && git clone --depth 1 --branch v1.5.0 https://github.com/VirusTotal/yara-x.git /tmp/yara-x \
  && cd /tmp/yara-x \
  && cargo cinstall -p yara-x-capi --release \
  && rm -rf /tmp/yara-x

ENV PATH="/usr/local/bin:$PATH"
