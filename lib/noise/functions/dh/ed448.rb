# frozen_string_literal: true

module Noise
  module Functions
    module DH
      class ED448
        DHLEN = 56
        def generate_keypair
          throw NotImplementedError
        end

        def dh(_key_pair, _public_key)
          throw NotImplementedError
        end

        def dhlen
          DHLEN
        end
      end
    end
  end
end
