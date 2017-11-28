# frozen_string_literal: true

module Noise
  module State
    autoload :CipherState, 'noise/state/cipher_state'
    autoload :HandshakeState, 'noise/state/handshake_state'
    autoload :SymmetricState, 'noise/state/symmetric_state'
  end
end
