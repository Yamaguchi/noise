# frozen_string_literal: true

module Noise
  module Functions
    module DH
      autoload :DH448, 'noise/functions/dh/dh448'
      autoload :DH25519, 'noise/functions/dh/dh25519'
      autoload :Secp256k1, 'noise/functions/dh/secp256k1'
    end
  end
end
