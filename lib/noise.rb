# frozen_string_literal: true

require 'noise/version'

require 'ecdsa'
require 'rbnacl'
require 'securerandom'

require 'noise/utils/hash'
require 'noise/utils/string'

module Noise
  autoload :Protocol, 'noise/protocol'
  autoload :Exceptions, 'noise/exceptions'
  autoload :Functions, 'noise/functions'
  autoload :State, 'noise/state'
end
