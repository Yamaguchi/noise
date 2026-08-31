# frozen_string_literal: true

module Noise
  module Exceptions
    autoload :DecryptError, 'noise/exceptions/decrypt_error'
    autoload :EncryptError, 'noise/exceptions/encrypt_error'
    autoload :HandshakeAlreadyFinishedError, 'noise/exceptions/handshake_already_finished_error'
    autoload :HandshakeNotFinishedError, 'noise/exceptions/handshake_not_finished_error'
    autoload :HandshakeNotStartedError, 'noise/exceptions/handshake_not_started_error'
    autoload :HandshakeTurnError, 'noise/exceptions/handshake_turn_error'
    autoload :InvalidNonceError, 'noise/exceptions/invalid_nonce_error'
    autoload :InvalidPublicKeyError, 'noise/exceptions/invalid_public_key_error'
    autoload :MaxNonceError, 'noise/exceptions/max_nonce_error'
    autoload :MessageTooLongError, 'noise/exceptions/message_too_long_error'
    autoload :MissingDependencyError, 'noise/exceptions/missing_dependency_error'
    autoload :ProtocolNameError, 'noise/exceptions/protocol_name_error'
    autoload :NoiseHandshakeError, 'noise/exceptions/noise_handshake_error'
    autoload :NoiseValidationError, 'noise/exceptions/noise_validation_error'
    autoload :NoisePSKError, 'noise/exceptions/noise_psk_error'
    autoload :PSKValueError, 'noise/exceptions/psk_value_error'
    autoload :UnsupportedModifierError, 'noise/exceptions/unsupported_modifier_error'
  end
end
