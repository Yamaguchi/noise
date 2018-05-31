# frozen_string_literal: true

module Noise
  module Exceptions
    class InvalidPublicKeyError < StandardError
      def initialize(public_key)
        @public_key = public_key
      end
    end
  end
end
