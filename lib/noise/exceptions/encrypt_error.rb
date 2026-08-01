# frozen_string_literal: true

module Noise
  module Exceptions
    class EncryptError < StandardError
      def initialize(cause)
        super
        @cause = cause
      end
    end
  end
end
