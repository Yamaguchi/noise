# frozen_string_literal: true

module Noise
  module Exceptions
    # Raised when a handshake message is written where one has to be read, or read where one has to
    # be written. A Noise handshake alternates between the two parties, so only one of the two is
    # legal at any point.
    class HandshakeTurnError < NoiseHandshakeError
    end
  end
end
