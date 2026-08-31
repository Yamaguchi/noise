# frozen_string_literal: true

module Noise
  module Exceptions
    # Raised when a handshake operation is called after the handshake has already finished.
    class HandshakeAlreadyFinishedError < NoiseHandshakeError
    end
  end
end
