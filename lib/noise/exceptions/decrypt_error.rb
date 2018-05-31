# frozen_string_literal: true

module Noise
  module Exceptions
    class DecryptError < StandardError
      def initialize(cause)
        @cause = cause
      end
    end
  end
end
