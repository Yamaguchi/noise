# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'noise/version'

Gem::Specification.new do |spec|
  spec.name = 'noise-ruby'
  spec.required_ruby_version = '>= 3.2'
  spec.version       = Noise::VERSION
  spec.authors       = ['Hajime Yamaguchi']
  spec.email         = ['gen.yamaguchi0@gmail.com']

  spec.summary       = 'A Ruby implementation of the Noise Protocol framework'
  spec.description   = 'A Ruby implementation of the Noise Protocol framework(http://noiseprotocol.org/).'
  spec.homepage      = 'https://github.com/Yamaguchi/noise'

  spec.files = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir = 'exe'
  spec.executables = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_development_dependency 'rake', '>= 12.3.3'
  spec.add_development_dependency 'rspec', '~> 3.0'

  spec.add_development_dependency 'rubocop'
  spec.add_development_dependency 'rubocop-rspec'
  spec.add_development_dependency 'simplecov'
  spec.add_development_dependency 'simplecov-json'

  # Optional backend. BLAKE3 is needed only when it appears in a protocol name, and it needs Rust
  # to build, so it is not a runtime dependency. Add it to your own Gemfile if you need it; see the
  # README.
  spec.add_development_dependency 'blake3'

  spec.add_runtime_dependency 'ecdsa'
  # The 448 DH function needs the raw key API (OpenSSL::PKey.new_raw_private_key and friends),
  # which arrived in openssl 3.0. Ruby 3.0 still ships 2.2 as its default gem, so the version has
  # to be requested explicitly rather than left to whatever the interpreter bundles.
  spec.add_runtime_dependency 'openssl', '>= 3.0'
  spec.add_runtime_dependency 'rbnacl'
  spec.add_runtime_dependency 'ruby-hmac'
end
