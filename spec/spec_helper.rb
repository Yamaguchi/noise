# frozen_string_literal: true

require 'bundler/setup'
require 'noise'


def use_secp256k1
  host_os = RbConfig::CONFIG['host_os']
  ENV['C_INCLUDE_PATH'] = File.expand_path('lib/include', File.dirname(__FILE__))
  case host_os
    when /darwin|mac os/
      ENV['LIBSECP256K1'] = File.expand_path('lib/libsecp256k1.dylib', File.dirname(__FILE__))
    when /linux/
      ENV['LIBSECP256K1'] = File.expand_path('lib/libsecp256k1.so', File.dirname(__FILE__))
    else
      raise "#{host_os} is an unsupported os."
  end
end

def use_goldilocks
  host_os = RbConfig::CONFIG['host_os']
  case host_os
    when /darwin|mac os/
      ENV['LIBGOLDILOCKS'] = File.expand_path('lib/libgoldilocks.dylib', File.dirname(__FILE__))
    when /linux/
      ENV['LIBGOLDILOCKS'] = File.expand_path('lib/libgoldilocks.so', File.dirname(__FILE__))
    else
      raise "#{host_os} is an unsupported os."
  end
end

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = '.rspec_status'

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end

  use_secp256k1
  use_goldilocks
end
