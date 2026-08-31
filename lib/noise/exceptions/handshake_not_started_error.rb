# frozen_string_literal: true

module Noise
  module Exceptions
    # Raised when an operation needs a handshake that Connection#start_handshake has not begun yet.
    class HandshakeNotStartedError < NoiseHandshakeError
    end
  end
end
