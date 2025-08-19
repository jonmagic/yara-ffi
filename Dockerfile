
FROM ruby:3.3

RUN apt-get update -qq \
  && apt-get install -y curl git unzip

WORKDIR /app

COPY . ./
RUN gem install bundler:2.2.15 \
  && bundle install

# Download and install YARA-X v1.5.0 release (Linux x86_64)
RUN curl -L "https://github.com/VirusTotal/yara-x/releases/download/v1.5.0/yara-x-v1.5.0-x86_64-unknown-linux-gnu.gz" -o /usr/local/bin/yara-x.gz \
  && gunzip /usr/local/bin/yara-x.gz \
  && chmod +x /usr/local/bin/yara-x

ENV PATH="/usr/local/bin:$PATH"
