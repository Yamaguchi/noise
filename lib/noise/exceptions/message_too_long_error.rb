# frozen_string_literal: true

module Noise
  module Exceptions
    # Raised when a transport message would exceed, or does exceed, the 65535 byte limit the Noise
    # specification places on every message. Kept apart from DecryptError so that a caller can tell a
    # badly framed message from a failed authentication, which has very different security meaning.
    class MessageTooLongError < StandardError
    end
  end
end
