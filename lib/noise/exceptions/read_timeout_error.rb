# frozen_string_literal: true

module Noise
  module Exceptions
    # Raised when a transport layer gave up waiting for the rest of a message to arrive.
    class ReadTimeoutError < RuntimeError
    end
  end
end
