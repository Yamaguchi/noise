# frozen_string_literal: true

require 'noise/version'

require 'ecdsa'
require 'logger'
require 'rbnacl'
require 'ruby_hmac'
require 'securerandom'

require 'noise/utils/hash'
require 'noise/utils/string'

module Noise
  autoload :Connection, 'noise/connection'
  autoload :Key, 'noise/key'
  autoload :KeyPair, 'noise/key_pair'
  autoload :Protocol, 'noise/protocol'
  autoload :Pattern, 'noise/pattern'
  autoload :Exceptions, 'noise/exceptions'
  autoload :Functions, 'noise/functions'
  autoload :State, 'noise/state'

  def self.logger
    @logger ||= Logger.new(STDOUT)
  end
end

def require_force(name)
  require name
  yield if block_given?
rescue LoadError => e
  Noise.logger.warn(e.message)
end
