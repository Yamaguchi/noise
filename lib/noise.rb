# frozen_string_literal: true

require 'noise/version'

require 'ecdsa'
require 'logger'
require 'rbnacl'
require 'ruby_hmac'
require 'securerandom'

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

  # Some DH and hash functions are backed by a gem, and often a system library, that is only needed
  # when the function appears in a protocol name. Loading one is therefore allowed to fail; the
  # failure is remembered and reported by optional_dependency! when the function is used.
  @unavailable_dependencies = {}

  class << self
    def logger
      @logger ||= Logger.new($stdout)
    end

    def require_optional(name)
      require name
      yield if block_given?
    rescue LoadError => e
      @unavailable_dependencies[name] = e.message
      logger.warn("Optional dependency '#{name}' is unavailable: #{e.message}")
    end

    def optional_dependency!(name)
      reason = @unavailable_dependencies[name]
      return if reason.nil?

      raise Noise::Exceptions::MissingDependencyError, "'#{name}' could not be loaded: #{reason}"
    end
  end
end
