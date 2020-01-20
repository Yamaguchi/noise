# frozen_string_literal: true

require_force('ed448') { Ed448.init }

module Noise
  module Functions
    module DH
      class ED448
        include Noise::Functions::DH::Kem::ED448

        DHLEN = Ed448::X448::X448_PRIVATE_BYTES

        def generate_keypair
          private_key = SecureRandom.random_bytes(DHLEN)
          public_key = Ed448::X448.derive_public_key(private_key)
          Noise::Key.new(private_key, public_key)
        end

        def dh(private_key, public_key)
          Ed448::X448.dh(public_key, private_key)
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
