# frozen_string_literal: true

module Noise
  module Exceptions
    autoload :DecryptError, 'noise/exceptions/decrypt_error'
    autoload :EncryptError, 'noise/exceptions/encrypt_error'
    autoload :InvalidPublicKeyError, 'noise/exceptions/invalid_public_key_error'
    autoload :MaxNonceError, 'noise/exceptions/max_nonce_error'
    autoload :ProtocolNameError, 'noise/exceptions/protocol_name_error'
    autoload :NoiseHandshakeError, 'noise/exceptions/noise_handshake_error'
    autoload :NoiseValidationError, 'noise/exceptions/noise_validation_error'
    autoload :NoisePSKError, 'noise/exceptions/noise_psk_error'
    autoload :PSKValueError, 'noise/exceptions/psk_value_error'
  end
end
