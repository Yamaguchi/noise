# frozen_string_literal: true

module Noise
  module Functions
    module DH
      autoload :ED448, 'noise/functions/dh/ed448'
      autoload :ED25519, 'noise/functions/dh/ed25519'
      autoload :Secp256k1, 'noise/functions/dh/secp256k1'
    end
  end
end
