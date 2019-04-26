# frozen_string_literal: true

module Noise
  module Functions
    module DH
      class ED25519
        DHLEN = 32
        def generate_keypair
          private_key = 1 + SecureRandom.random_number(RbNaCl::GroupElement::STANDARD_GROUP_ORDER - 1)
          scalar_as_string = ECDSA::Format::IntegerOctetString.encode(private_key, 32)
          public_key = RbNaCl::GroupElements::Curve25519.base.mult(scalar_as_string)
          Noise::Key.new(ECDSA::Format::IntegerOctetString.encode(private_key, 32), public_key.to_bytes)
        end

        def dh(private_key, public_key)
          RbNaCl::GroupElement.new(public_key).mult(private_key).to_bytes
        end

        def dhlen
          DHLEN
        end

        def self.from_private(private_key)
          public_key = RbNaCl::GroupElements::Curve25519.base.mult(private_key)
          Noise::Key.new(private_key, public_key.to_bytes)
        end
      end
    end
  end
end
