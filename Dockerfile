# check=skip=FromPlatformFlagConstDisallowed
# The test suite loads the x86_64 libsecp256k1 / libgoldilocks bundled in spec/lib, and
# spec/spec_helper.rb points at them unconditionally, so this image has to be linux/amd64
# even on an arm64 host. It mirrors the CI runner (ubuntu x86_64).
FROM --platform=linux/amd64 ruby:3.3

# libsodium: dlopen'd by rbnacl, which lib/noise.rb requires unconditionally.
# cargo: the blake3 gem is a Rust extension and is built at install time.
# git: noise.gemspec calls `git ls-files` while the gemspec is evaluated.
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends build-essential git libsodium23 cargo \
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
