# frozen_string_literal: true

module Noise
  module Exceptions
    # Raised when a nonce given to CipherState#nonce= is not an unsigned 64-bit integer.
    class InvalidNonceError < RuntimeError
    end
  end
end
