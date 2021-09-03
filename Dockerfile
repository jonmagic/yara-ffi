FROM ruby:2.6.6

RUN apt-get update -qq
RUN apt-get install -y flex bison

WORKDIR /app

COPY . ./
RUN gem install bundler:2.2.15
RUN bundle install

RUN git clone --recursive --branch v4.1.1 https://github.com/VirusTotal/yara.git /tmp/yara && \
  cd /tmp/yara/ && \
  ./bootstrap.sh && \
  ./configure && \
  make && \
  make install
