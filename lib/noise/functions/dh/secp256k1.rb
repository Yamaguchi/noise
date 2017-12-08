# frozen_string_literal: true

module Noise
  module Functions
    module DH
      class Secp256k1
        def generate_keypair
          group = ECDSA::Group::Secp256k1
          private_key = 1 + SecureRandom.random_number(group.order - 1)
          public_key = group.generator.multiply_by_scalar(private_key)
          [
            ECDSA::Format::IntegerOctetString.encode(private_key, 32),
            ECDSA::Format::PointOctetString.encode(public_key, compression: true)
          ]
        end

        def dh(private_key, public_key)
          group = ECDSA::Group::Secp256k1
          point = ECDSA::Format::PointOctetString.decode(public_key, group)
          scalar = ECDSA::Format::IntegerOctetString.decode(private_key)
          point = point.multiply_by_scalar(scalar)
          ECDSA::Format::PointOctetString.encode(point, compression: true)
        end

        def dhlen
          64
        end

        def self.from_private(private_key)
          group = ECDSA::Group::Secp256k1
          scalar = ECDSA::Format::IntegerOctetString.decode(private_key)
          point = group.generator.multiply_by_scalar(scalar)
          [private_key, ECDSA::Format::PointOctetString.encode(point, compression: true)]
        end

        def self.from_public(public_key)
          [nil, public_key]
        end
      end
    end
  end
end
