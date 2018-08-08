# frozen_string_literal: true

require 'noise/version'

require 'ecdsa'
require 'rbnacl/libsodium'
require 'ruby_hmac'
require 'secp256k1'
require 'securerandom'

require 'noise/utils/hash'
require 'noise/utils/string'

module Noise
  autoload :Connection, 'noise/connection'
  autoload :KeyPair, 'noise/key_pair'
  autoload :Protocol, 'noise/protocol'
  autoload :Pattern, 'noise/pattern'
  autoload :Exceptions, 'noise/exceptions'
  autoload :Functions, 'noise/functions'
  autoload :State, 'noise/state'
end
