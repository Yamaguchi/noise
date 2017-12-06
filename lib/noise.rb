# frozen_string_literal: true

require 'noise/version'

require 'ecdsa'
require 'rbnacl'
require 'ruby_hmac'
require 'securerandom'

require 'noise/utils/hash'
require 'noise/utils/string'

module Noise
  autoload :Connection, 'noise/connection'
  autoload :Protocol, 'noise/protocol'
  autoload :Pattern, 'noise/pattern'
  autoload :Exceptions, 'noise/exceptions'
  autoload :Functions, 'noise/functions'
  autoload :State, 'noise/state'
end
