# frozen_string_literal: true

require 'noise/version'

require 'ecdsa'
require 'openssl'
require 'ruby_hmac'
require 'securerandom'

require 'noise/utils/string'

module Noise
  autoload :Connection, 'noise/connection'
  autoload :Key, 'noise/key'
  autoload :KeyPair, 'noise/key_pair'
  autoload :Protocol, 'noise/protocol'
  autoload :Pattern, 'noise/pattern'
  # Noise::Modifier and Noise::Token are declared in the same file as Noise::Pattern.
  autoload :Modifier, 'noise/pattern'
  autoload :Token, 'noise/pattern'
  autoload :ProtocolName, 'noise/protocol_name'
  autoload :Exceptions, 'noise/exceptions'
  autoload :Functions, 'noise/functions'
  autoload :State, 'noise/state'
  autoload :Transport, 'noise/transport'

  # Some DH and hash functions are backed by a gem, and often a system library, that is only needed
  # when the function appears in a protocol name. Loading one is therefore allowed to fail; the
  # failure is remembered and reported by optional_dependency! when the function is used.
  @unavailable_dependencies = {}

  class << self
    # Requires an optional backend gem and yields once it is loaded. A LoadError is not fatal:
    # the reason is recorded so optional_dependency! can raise it later, and a warning goes to
    # $stderr so the missing backend is visible at load time. Kernel#warn is used rather than a
    # Logger because logger is no longer a default gem on Ruby 4.0, and this single message does
    # not justify a runtime dependency on it.
    def require_optional(name)
      require name
    rescue LoadError => e
      @unavailable_dependencies[name] = e.message
      warn("Optional dependency '#{name}' is unavailable: #{e.message}")
    else
      # The block runs outside the rescue on purpose: a LoadError raised by the block itself is
      # about something other than this dependency, and swallowing it here would hide the cause.
      yield if block_given?
    end

    # Raises MissingDependencyError if the named optional backend failed to load earlier. Call it
    # from the entry point of a function that needs the backend, so the failure surfaces where the
    # backend is used rather than at require time.
    def optional_dependency!(name)
      reason = @unavailable_dependencies[name]
      return if reason.nil?

      raise Noise::Exceptions::MissingDependencyError, "'#{name}' could not be loaded: #{reason}"
    end
  end
end
