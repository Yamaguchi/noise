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

        # Computes the X25519 shared secret for the given remote public key.
        #
        # RbNaCl reports a public key it cannot use in two different ways: a wrong length
        # raises RbNaCl::LengthError, and an all-zero or low-order point raises
        # RbNaCl::CryptoError. Both are translated to InvalidPublicKeyError so that a
        # caller handling a peer-supplied key rescues the same class for every DH function.
        # The length is checked before the call so that RbNaCl::LengthError raised for a
        # malformed private key keeps propagating as itself.
        def dh(private_key, public_key)
          raise Noise::Exceptions::InvalidPublicKeyError, public_key unless public_key.bytesize == DHLEN

          RbNaCl::GroupElement.new(public_key).mult(private_key).to_bytes
        rescue RbNaCl::CryptoError
          raise Noise::Exceptions::InvalidPublicKeyError, public_key
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
