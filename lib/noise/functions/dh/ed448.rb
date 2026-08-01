# frozen_string_literal: true

Noise.require_optional('ed448') { Ed448.init }

module Noise
  module Functions
    module DH
      class ED448
        # Ed448::X448::X448_PRIVATE_BYTES, spelled out so this file loads without the gem.
        DHLEN = 56

        def initialize
          Noise.optional_dependency!('ed448')
        end

        def generate_keypair
          private_key = SecureRandom.random_bytes(DHLEN)
          public_key = Ed448::X448.derive_public_key(private_key)
          Noise::Key.new(private_key, public_key)
        end

        # Computes the X448 shared secret for the given remote public key.
        #
        # Ed448::X448.dh raises a plain RuntimeError when libgoldilocks rejects the base
        # point because it lies in a small subgroup, and it silently zero-pads a public key
        # shorter than DHLEN. The length is checked up front and the RuntimeError is
        # translated, so an unusable remote key always surfaces as InvalidPublicKeyError,
        # the same class the other DH functions raise.
        def dh(private_key, public_key)
          raise Noise::Exceptions::InvalidPublicKeyError, public_key unless public_key.bytesize == DHLEN

          Ed448::X448.dh(public_key, private_key)
        rescue RuntimeError
          raise Noise::Exceptions::InvalidPublicKeyError, public_key
        end

        def dhlen
          DHLEN
        end

        def self.from_private(private_key)
          public_key = Ed448::X448.derive_public_key(private_key)
          Noise::Key.new(private_key, public_key)
        end
      end
    end
  end
end
