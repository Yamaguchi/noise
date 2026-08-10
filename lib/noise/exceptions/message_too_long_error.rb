# frozen_string_literal: true

module Noise
  module Exceptions
    # Raised when a message would exceed, or does exceed, the 65535 byte limit the Noise
    # specification places on every message. Raised from the handshake and the transport paths
    # alike, so that a caller handling "the peer sent something too long" rescues one class rather
    # than one per phase.
    #
    # It covers over-long messages only, and the other framing errors keep their own classes: a
    # truncated handshake message raises NoiseHandshakeError, and a transport message shorter than
    # the authentication tag raises DecryptError. A caller that treats every framing error alike
    # has to rescue all three.
    #
    # Kept apart from DecryptError so that a badly framed message can be told from a failed
    # authentication, which has very different security meaning.
    class MessageTooLongError < StandardError
    end
  end
end
