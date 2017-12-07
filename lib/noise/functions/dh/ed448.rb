module Noise
  module Functions
    module DH
      class ED448
        DHLEN = 56
        def generate_keypair
          throw NotImplementedError
        end

        def dh(key_pair, public_key)
          throw NotImplementedError
        end

        def dhlen
          DHLEN
        end

        def self.from_private(private_key)
        end
        def self.from_public(private_key)
        end
      end
    end
  end
end
