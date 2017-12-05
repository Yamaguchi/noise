module Noise
  module Functions
    module DH
      class DH25519
        DHLEN = 32
        def generate_keypair
          private_key = RbNaCl::Signatures::Ed25519::SigningKey.generate
          public_key = private_key.verify_key
          [private_key.to_bytes, public_key.to_bytes]
        end

        def dh(private_key, public_key)
          puts public_key.bth, private_key.bth
          point = RbNaCl::GroupElement.new(public_key).mult(private_key)
          point.to_bytes
        end

        def dhlen
          DHLEN
        end

        def self.from_private(private_key)
          private_key = RbNaCl::GroupElements::Curve25519.new(private_key)
          public_key = RbNaCl::GroupElements::Curve25519.base.mult(private_key)
          [private_key.to_bytes, public_key.to_bytes]
        end

        def self.from_public(public_key)
          public_key = RbNaCl::Signatures::Ed25519::VerifyKey.new(public_key)
          [nil, public_key.to_bytes]
        end
      end
    end
  end
end
