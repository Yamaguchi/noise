# frozen_string_literal: true

module Noise
  module Functions
    module DH
      class Secp256k1
        def generate_keypair
          group = ECDSA::Group::Secp256k1
          private_key = 1 + SecureRandom.random_number(group.order - 1)
          public_key = group.generator.multiply_by_scalar(private_key)
          [private_key, public_key]
        end

        def dh(private_key, public_key)
          public_key.multiply_by_scalar(private_key)
        end

        def dhlen
          64
        end
        def self.from_private(private_key)
        end
        def self.from_public(private_key)
        end
      end
    end
  end
end
