# frozen_string_literal: true

begin
  require 'secp256k1'
rescue LoadError
end


module Noise
  module Functions
    module DH
      class Secp256k1
        def generate_keypair
          group = ECDSA::Group::Secp256k1
          private_key = 1 + SecureRandom.random_number(group.order - 1)
          public_key = group.generator.multiply_by_scalar(private_key)
          Noise::Key.new(
            ECDSA::Format::IntegerOctetString.encode(private_key, 32),
            ECDSA::Format::PointOctetString.encode(public_key, compression: true)
          )
        end

        def dh(private_key, public_key)
          key = ::Secp256k1::PublicKey.new(pubkey: public_key, raw: true)
          key.ecdh(private_key)
        rescue ::Secp256k1::AssertError => _
          raise Noise::Exceptions::InvalidPublicKeyError.new(public_key)
        end

        def dhlen
          33
        end

        def self.from_private(private_key)
          group = ECDSA::Group::Secp256k1
          scalar = ECDSA::Format::IntegerOctetString.decode(private_key)
          point = group.generator.multiply_by_scalar(scalar)
          Noise::Key.new(private_key, ECDSA::Format::PointOctetString.encode(point, compression: true))
        end
      end
    end
  end
end
