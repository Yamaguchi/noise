# frozen_string_literal: true

Noise.require_optional 'secp256k1'

module Noise
  module Functions
    module DH
      class Secp256k1
        # Length of a compressed secp256k1 point. libsecp256k1 also accepts the 65-byte
        # uncompressed form, but Noise exchanges only the compressed one.
        DHLEN = 33

        def initialize
          Noise.optional_dependency!('secp256k1')
        end

        def generate_keypair
          group = ECDSA::Group::Secp256k1
          private_key = 1 + SecureRandom.random_number(group.order - 1)
          public_key = group.generator.multiply_by_scalar(private_key)
          Noise::Key.new(
            ECDSA::Format::IntegerOctetString.encode(private_key, 32),
            ECDSA::Format::PointOctetString.encode(public_key, compression: true)
          )
        end

        # Computes the ECDH shared secret for the given remote public key.
        #
        # A point that is not on the curve makes libsecp256k1 raise Secp256k1::AssertError,
        # while a public key of any other length raises ArgumentError before the point is
        # even parsed. Both are translated to InvalidPublicKeyError, matching the other DH
        # functions. The length is checked here rather than left to the gem so that
        # ArgumentError raised for a malformed private key keeps propagating as itself.
        def dh(private_key, public_key)
          raise Noise::Exceptions::InvalidPublicKeyError, public_key unless public_key.bytesize == DHLEN

          key = ::Secp256k1::PublicKey.new(pubkey: public_key, raw: true)
          key.ecdh(private_key)
        rescue ::Secp256k1::AssertError
          raise Noise::Exceptions::InvalidPublicKeyError, public_key
        end

        def dhlen
          DHLEN
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
