# frozen_string_literal: true

module Noise
  module Exceptions
    autoload :MaxNonceError, 'noise/exceptions/max_nonce_error'
    autoload :ProtocolNameError, 'noise/exceptions/protocol_name_error'
    autoload :NoiseHandshakeError, 'noise/exceptions/noise_handshake_error'
    autoload :NoiseValidationError, 'noise/exceptions/noise_validation_error'
  end
end
