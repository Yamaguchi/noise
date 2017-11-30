module Noise
  module Functions
    module DH
      class DH25519
        DHLEN = 32
        def generate_keypair
          private_key = RbNaCl::Signatures::Ed25519::SigningKey.generate
          public_key = private_key.verify_key.to_bytes
          [private_key.to_bytes, public_key]
        end

        def dh(private_key, public_key)
          RbNaCl::GroupElement.new(public_key).mult(private_key)
        end

        def dhlen
          DHLEN
        end
      end
    end
  end
end
