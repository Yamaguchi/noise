module Noise
  module Functions
    module DH
      class DH448
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
      end
    end
  end
end