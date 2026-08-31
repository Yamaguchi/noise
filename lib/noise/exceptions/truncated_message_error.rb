# frozen_string_literal: true

module Noise
  module Exceptions
    # Raised when a stream ends part way through a message that a transport layer was reading.
    class TruncatedMessageError < RuntimeError
    end
  end
end
