# A Linux environment close to the CI runner, for checking a change against the Ruby version CI
# lints with. Nothing in the suite is architecture specific, so the image builds for the host
# architecture and needs no emulation.
FROM ruby:4.0

# libsodium: dlopen'd by rbnacl, which lib/noise.rb requires unconditionally.
# git: noise.gemspec calls `git ls-files` while the gemspec is evaluated.
# No Rust toolchain: the blake3-rb gem ships a precompiled binary for this platform.
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends build-essential git libsodium23 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work

# Install the gems from the dependency definitions alone so the layer stays cached when only
# the source changes. Gems live in BUNDLE_PATH (/usr/local/bundle), outside /work, so mounting
# the working tree over /work at run time does not hide them.
#
# Gemfile.lock is gitignored, hence the glob: it is copied when the host has one so the image
# installs the exact versions the mounted lock will ask for at run time, and skipped otherwise.
COPY Gemfile* noise.gemspec ./
COPY lib/noise/version.rb lib/noise/version.rb
RUN bundle install

# Run with the working tree mounted:
#   docker run --rm -v "$PWD":/work noise-dev
#   docker run --rm -v "$PWD":/work noise-dev bundle exec rubocop
CMD ["bundle", "exec", "rspec"]
