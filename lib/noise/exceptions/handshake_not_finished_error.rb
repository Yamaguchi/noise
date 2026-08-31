# frozen_string_literal: true

module Noise
  module Exceptions
    # Raised when a transport operation is called while the handshake is still running.
    class HandshakeNotFinishedError < NoiseHandshakeError
    end
  end
end
