# frozen_string_literal: true

module Noise
  module Exceptions
    class InvalidPublicKeyError < StandardError
      attr_reader :public_key

      def initialize(public_key)
        super("Invalid public key: #{public_key.unpack1('H*')}")
        @public_key = public_key
      end
    end
  end
end
