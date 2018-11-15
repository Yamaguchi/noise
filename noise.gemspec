# frozen_string_literal: true

lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'noise/version'

Gem::Specification.new do |spec|
  spec.name          = 'noise-ruby'
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

  spec.add_development_dependency 'bundler', '~> 1.15'
  spec.add_development_dependency 'rake', '~> 10.0'
  spec.add_development_dependency 'rspec', '~> 3.0'

  spec.add_runtime_dependency 'secp256k1-ruby'
  spec.add_runtime_dependency 'ecdsa'
  spec.add_runtime_dependency 'rbnacl'
  spec.add_runtime_dependency 'ruby-hmac'
end
